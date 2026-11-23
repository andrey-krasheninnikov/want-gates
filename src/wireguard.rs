use crate::invalid;
use crate::policy::{Network, domain_name};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub addresses: Vec<String>,
    pub private_key: String,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub dns: Option<IpAddr>,
    pub mtu: Option<u16>,
    pub keepalive: Option<u16>,
}

pub fn unicast(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && ip != IpAddr::V4(Ipv4Addr::BROADCAST)
        && !matches!(ip, IpAddr::V6(v) if v.to_ipv4_mapped().is_some() || v.is_unicast_link_local())
}

pub fn endpoint(value: &str) -> io::Result<(String, u16)> {
    let error = || invalid("invalid WireGuard endpoint; use an IP or hostname with a nonzero port");
    if let Ok(endpoint) = value.parse::<SocketAddr>() {
        if !unicast(endpoint.ip())
            || endpoint.port() == 0
            || matches!(endpoint, SocketAddr::V6(v) if v.scope_id() != 0)
        {
            return Err(error());
        }
        return Ok((endpoint.ip().to_string(), endpoint.port()));
    }
    let (host, port) = value.rsplit_once(':').ok_or_else(error)?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(error)?;
    Ok((domain_name(host).map_err(|_| error())?, port))
}

fn key(value: &str) -> io::Result<()> {
    let mut bytes = [0; 32];
    if value.len() != 44
        || STANDARD.decode_slice(value, &mut bytes).ok() != Some(32)
        || bytes == [0; 32]
    {
        return Err(invalid(
            "invalid WireGuard key; expected a nonzero 32-byte base64 key",
        ));
    }
    Ok(())
}

fn host_prefix(value: &str) -> io::Result<String> {
    let error = || invalid("invalid WireGuard interface address");
    let network = Network::parse(value).map_err(|_| error())?;
    let host: IpAddr = value
        .split('/')
        .next()
        .unwrap()
        .parse()
        .map_err(|_| error())?;
    if !unicast(host) {
        return Err(error());
    }
    Ok(format!("{host}/{}", network.prefix))
}

impl Profile {
    fn normalize(&mut self) -> io::Result<()> {
        key(&self.private_key)?;
        key(&self.public_key)?;
        if let Some(shared) = &self.preshared_key {
            key(shared)?;
        }
        let (host, port) = endpoint(&self.endpoint)?;
        self.endpoint = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        if self.addresses.is_empty()
            || self.addresses.len() > 32
            || self.allowed_ips.is_empty()
            || self.allowed_ips.len() > 256
        {
            return Err(invalid(
                "WireGuard requires 1 to 32 addresses and 1 to 256 AllowedIPs",
            ));
        }
        for address in &mut self.addresses {
            *address = host_prefix(address)?;
        }
        let mut hosts = BTreeSet::new();
        if self
            .addresses
            .iter()
            .any(|a| !hosts.insert(a.split('/').next().unwrap()))
        {
            return Err(invalid("duplicate WireGuard interface address"));
        }
        for cidr in &mut self.allowed_ips {
            *cidr = Network::parse(cidr)
                .map_err(|_| invalid("invalid WireGuard AllowedIPs"))?
                .canonical();
        }
        let mut routes = BTreeSet::new();
        self.allowed_ips.retain(|cidr| routes.insert(cidr.clone()));
        if self.dns.is_some_and(|ip| !unicast(ip)) {
            return Err(invalid("expected one numeric WireGuard DNS server"));
        }
        let minimum_mtu = if self.addresses.iter().any(|address| address.contains(':')) {
            1280
        } else {
            68
        };
        if self.mtu.is_some_and(|mtu| mtu < minimum_mtu) {
            return Err(invalid(
                "invalid WireGuard MTU for the interface address families",
            ));
        }
        Ok(())
    }
}

pub fn decoded_profile(value: &Value) -> io::Result<Profile> {
    if value.as_object().is_none_or(|fields| fields.len() != 2) || value["protocol"] != "wireguard"
    {
        return Err(invalid("invalid saved WireGuard profile"));
    }
    let mut profile: Profile = serde_json::from_value(value["settings"].clone())
        .map_err(|_| invalid("invalid saved WireGuard settings"))?;
    profile.normalize()?;
    Ok(profile)
}

pub fn parse(input: &str) -> io::Result<Value> {
    if input.len() > crate::store::MAX_PROFILE {
        return Err(invalid("profile exceeds 1 MiB"));
    }
    if input.trim_start().starts_with('{') {
        let value = crate::profile::strict_json(input)
            .map_err(|_| invalid("invalid saved WireGuard profile"))?;
        return Ok(json!({"protocol":"wireguard","settings":decoded_profile(&value)?}));
    }

    let mut section = "";
    let mut interface = false;
    let mut peer = false;
    let mut fields = BTreeMap::new();
    let mut addresses = Vec::new();
    let mut allowed_ips = Vec::new();
    for line in input.lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        if line.eq_ignore_ascii_case("[Interface]") {
            if interface {
                return Err(invalid("duplicate WireGuard section"));
            }
            interface = true;
            section = "interface";
            continue;
        }
        if line.eq_ignore_ascii_case("[Peer]") {
            if peer {
                return Err(invalid(
                    "duplicate WireGuard section; only one peer is supported",
                ));
            }
            peer = true;
            section = "peer";
            continue;
        }
        let (field, value) = line
            .split_once('=')
            .ok_or_else(|| invalid("invalid WireGuard profile line"))?;
        let field = field.trim().to_ascii_lowercase();
        let value = value.trim();
        match (section, field.as_str()) {
            ("interface", "address") => {
                addresses.extend(value.split(',').map(|part| part.trim().to_owned()));
                continue;
            }
            ("peer", "allowedips") => {
                allowed_ips.extend(value.split(',').map(|part| part.trim().to_owned()));
                continue;
            }
            ("interface", "privatekey" | "dns" | "mtu")
            | ("peer", "publickey" | "presharedkey" | "endpoint" | "persistentkeepalive") => {}
            _ => return Err(invalid("unsupported WireGuard profile field")),
        }
        if fields.insert(field, value).is_some() {
            return Err(invalid("duplicate WireGuard profile field"));
        }
    }

    let required = |field| {
        fields
            .get(field)
            .map(|value| (*value).to_owned())
            .ok_or_else(|| invalid("WireGuard profile requires PrivateKey, PublicKey and Endpoint"))
    };
    let mut profile = Profile {
        addresses,
        allowed_ips,
        private_key: required("privatekey")?,
        public_key: required("publickey")?,
        preshared_key: fields.get("presharedkey").map(|v| (*v).to_owned()),
        endpoint: required("endpoint")?,
        dns: fields
            .get("dns")
            .map(|v| {
                v.parse()
                    .map_err(|_| invalid("expected one numeric WireGuard DNS server"))
            })
            .transpose()?,
        mtu: fields
            .get("mtu")
            .map(|v| v.parse().map_err(|_| invalid("invalid WireGuard MTU")))
            .transpose()?,
        keepalive: fields
            .get("persistentkeepalive")
            .map(|v| {
                if v.eq_ignore_ascii_case("off") {
                    Ok(0)
                } else {
                    v.parse()
                        .map_err(|_| invalid("invalid WireGuard PersistentKeepalive"))
                }
            })
            .transpose()?,
    };
    profile.normalize()?;
    Ok(json!({"protocol":"wireguard","settings":profile}))
}
