use crate::invalid;
use serde::{Deserialize, Serialize};
use std::io;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub group_id: String,
    pub destination: String,
    pub revision: u64,
}

pub struct Network {
    pub address: IpAddr,
    pub prefix: u8,
}
impl Network {
    pub fn parse(input: &str) -> io::Result<Self> {
        let (address, prefix) = input
            .split_once('/')
            .map_or((input, None), |(a, p)| (a, Some(p)));
        let address: IpAddr = address
            .parse()
            .map_err(|_| invalid("destination must be an IP address or CIDR"))?;
        if matches!(address, IpAddr::V6(a) if a.to_ipv4_mapped().is_some()) {
            return Err(invalid("use IPv4 notation for mapped IPv4 addresses"));
        }
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= bits)
                .ok_or_else(|| invalid("invalid CIDR prefix"))?,
            None => bits,
        };
        let number = match address {
            IpAddr::V4(a) => u32::from(a) as u128,
            IpAddr::V6(a) => u128::from(a),
        };
        let masked = if prefix == 0 {
            0
        } else {
            (number >> (bits - prefix)) << (bits - prefix)
        };
        Ok(Self {
            address: if bits == 32 {
                IpAddr::V4((masked as u32).into())
            } else {
                IpAddr::V6(masked.into())
            },
            prefix,
        })
    }
    pub fn canonical(&self) -> String {
        format!("{}/{}", self.address, self.prefix)
    }
    pub fn contains(&self, address: IpAddr) -> bool {
        if address.is_ipv4() != self.address.is_ipv4() {
            return false;
        }
        Self::parse(&format!("{address}/{}", self.prefix)).is_ok_and(|n| n.address == self.address)
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<NameProbe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_ipv4: Option<HttpProbe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_ipv4: Option<DnsProbe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_ipv6: Option<HttpProbe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_ipv6: Option<DnsProbe>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpProbe {
    pub url: String,
    #[serde(default = "status_ok")]
    pub expected_status: u16,
}
fn status_ok() -> u16 {
    200
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsProbe {
    pub server: String,
    pub query_name: String,
    pub query_type: String,
}
impl HttpProbe {
    pub fn address(&self) -> io::Result<IpAddr> {
        let url = url::Url::parse(&self.url).map_err(|_| invalid("invalid HTTP probe URL"))?;
        if url.scheme() != "http"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
            || self.url.len() > 2048
            || !(200..=599).contains(&self.expected_status)
        {
            return Err(invalid(
                "HTTP probes require an http URL with a literal IP, no credentials, query or fragment, and a final status",
            ));
        }
        match url.host() {
            Some(url::Host::Ipv4(a)) => Ok(a.into()),
            Some(url::Host::Ipv6(a)) => Ok(a.into()),
            _ => Err(invalid("HTTP probe host must be a literal IP address")),
        }
    }
}
impl DnsProbe {
    pub fn address(&self) -> io::Result<SocketAddr> {
        let address: SocketAddr = self
            .server
            .parse()
            .map_err(|_| invalid("DNS probe server must be an IP:port"))?;
        let name = self.query_name.trim_end_matches('.');
        if address.port() == 0
            || name.is_empty()
            || name.len() > 253
            || name.split('.').any(|l| {
                l.is_empty()
                    || l.len() > 63
                    || !l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                    || l.starts_with('-')
                    || l.ends_with('-')
            })
            || !matches!(self.query_type.as_str(), "A" | "AAAA")
        {
            return Err(invalid(
                "DNS probes require a valid server, ASCII name, and A or AAAA query type",
            ));
        }
        Ok(address)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameProbe {
    pub query_name: String,
    pub query_type: String,
}
impl Probes {
    pub fn validate(&self) -> io::Result<()> {
        if let Some(probe) = &self.dns {
            domain_name(&probe.query_name)?;
            if !matches!(probe.query_type.as_str(), "A" | "AAAA") {
                return Err(invalid("DNS check requires A or AAAA"));
            }
        }
        for (probe, v4) in [(&self.tcp_ipv4, true), (&self.tcp_ipv6, false)] {
            if let Some(p) = probe
                && p.address()?.is_ipv4() != v4
            {
                return Err(invalid(
                    "HTTP probe IP family does not match its capability",
                ));
            }
        }
        for (probe, v4) in [(&self.udp_ipv4, true), (&self.udp_ipv6, false)] {
            if let Some(p) = probe
                && p.address()?.is_ipv4() != v4
            {
                return Err(invalid("DNS probe IP family does not match its capability"));
            }
        }
        Ok(())
    }
}

pub struct Resolver {
    pub network: &'static str,
    pub address: SocketAddr,
}
impl Resolver {
    pub fn parse(value: &str) -> io::Result<Self> {
        let (network, endpoint) = if let Some(v) = value.strip_prefix("udp://") {
            ("udp", v)
        } else if let Some(v) = value.strip_prefix("tcp://") {
            ("tcp", v)
        } else {
            return Err(invalid("DNS requires udp://IP:port or tcp://IP:port"));
        };
        let address: SocketAddr = endpoint
            .parse()
            .map_err(|_| invalid("DNS requires a literal IP and nonzero port"))?;
        if address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || matches!(address.ip(), IpAddr::V6(a) if a.to_ipv4_mapped().is_some())
            || matches!(address, SocketAddr::V6(a) if a.scope_id() != 0)
        {
            return Err(invalid(
                "DNS requires a unicast IP and nonzero port without a scope ID",
            ));
        }
        Ok(Self { network, address })
    }
    pub fn canonical(&self) -> String {
        format!("{}://{}", self.network, self.address)
    }
    pub fn capability(&self) -> String {
        format!(
            "{}_ipv{}",
            self.network,
            if self.address.is_ipv4() { 4 } else { 6 }
        )
    }
}

pub fn domain_name(value: &str) -> io::Result<String> {
    let raw = value.strip_suffix('.').unwrap_or(value);
    if raw.is_empty()
        || raw.len() > 1024
        || raw
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "/:?#@%\\*[]".contains(c))
    {
        return Err(invalid("invalid domain name"));
    }
    let url::Host::Domain(name) =
        url::Host::parse(raw).map_err(|_| invalid("invalid domain name"))?
    else {
        return Err(invalid("domain name must not be an IP address"));
    };
    if name.len() > 253
        || name.split('.').any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.starts_with('-')
                || l.ends_with('-')
                || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(invalid("invalid domain labels"));
    }
    Ok(name.to_ascii_lowercase())
}

pub struct Domain {
    pub name: String,
    pub exact: bool,
}
impl Domain {
    pub fn parse(value: &str) -> io::Result<Self> {
        let (exact, name) = value
            .strip_prefix("full:")
            .map_or((false, value), |v| (true, v));
        Ok(Self {
            name: domain_name(name)?,
            exact,
        })
    }
    pub fn canonical(&self) -> String {
        if self.exact {
            format!("full:{}", self.name)
        } else {
            self.name.clone()
        }
    }
    pub fn pattern(&self) -> String {
        format!(
            "{}:{}",
            if self.exact { "full" } else { "domain" },
            self.name
        )
    }
    pub fn specificity(&self) -> (usize, bool) {
        (self.name.split('.').count(), self.exact)
    }
    pub fn matches(&self, name: &str) -> bool {
        name == self.name
            || (!self.exact
                && name
                    .strip_suffix(&self.name)
                    .is_some_and(|v| v.ends_with('.')))
    }
}

pub fn destination(value: &str) -> io::Result<String> {
    if let Ok(network) = Network::parse(value) {
        return Ok(network.canonical());
    }
    Domain::parse(value).map(|d| d.canonical())
}
