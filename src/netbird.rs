use crate::{invalid, policy::domain_name, wireguard::unicast};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io;
use std::net::IpAddr;
use url::{Host, Url};

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Private,
    Exit,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ControlEndpoint {
    pub host: String,
    pub port: u16,
    pub transport: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub management_url: String,
    pub mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_network_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    control_endpoints: Vec<ControlEndpoint>,
}

pub fn network_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn endpoint_host(value: &str) -> io::Result<String> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return unicast(ip)
            .then(|| ip.to_string())
            .ok_or_else(|| invalid("NetBird endpoint must be a unicast address"));
    }
    domain_name(value).map_err(|_| invalid("invalid NetBird endpoint hostname"))
}

pub fn https_url(value: &str) -> io::Result<Url> {
    let error = || invalid("NetBird requires an HTTPS URL without embedded credentials");
    let url = Url::parse(value).map_err(|_| error())?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host().is_none()
        || url.port() == Some(0)
        || value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return Err(error());
    }
    Ok(url)
}

impl Profile {
    fn management(&self) -> io::Result<ControlEndpoint> {
        let url = https_url(&self.management_url)?;
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(invalid("NetBird management URL must be an HTTPS origin"));
        }
        let host = match url.host().unwrap() {
            Host::Domain(host) => endpoint_host(host)?,
            Host::Ipv4(ip) => endpoint_host(&ip.to_string())?,
            Host::Ipv6(ip) => endpoint_host(&ip.to_string())?,
        };
        Ok(ControlEndpoint {
            host,
            port: url.port().unwrap_or(443),
            transport: "tcp".into(),
        })
    }

    pub fn endpoints(&self) -> io::Result<Vec<ControlEndpoint>> {
        let mut endpoints = self.control_endpoints.clone();
        endpoints.push(self.management()?);
        endpoints.sort();
        endpoints.dedup();
        Ok(endpoints)
    }

    fn validate(mut self) -> io::Result<Self> {
        let management = self.management()?;
        self.management_url = https_url(&self.management_url)?
            .to_string()
            .trim_end_matches('/')
            .to_owned();
        match (self.mode, self.exit_network_id.as_deref()) {
            (Mode::Private, None) => {}
            (Mode::Exit, Some(id)) if network_id(id) => {}
            _ => {
                return Err(invalid(
                    "NetBird exit mode requires exactly one valid exit network ID",
                ));
            }
        }
        if self.control_endpoints.len() > 31 {
            return Err(invalid("NetBird control endpoint limit exceeded"));
        }
        for endpoint in &mut self.control_endpoints {
            endpoint.host = endpoint_host(&endpoint.host)?;
            if endpoint.port == 0 || !matches!(endpoint.transport.as_str(), "tcp" | "udp") {
                return Err(invalid(
                    "NetBird endpoints require a port and tcp or udp transport",
                ));
            }
        }
        self.control_endpoints.sort();
        self.control_endpoints.dedup();
        self.control_endpoints
            .retain(|endpoint| endpoint != &management);
        Ok(self)
    }
}

pub fn decoded_profile(value: &Value) -> io::Result<Profile> {
    if value.as_object().is_none_or(|fields| fields.len() != 2) || value["protocol"] != "netbird" {
        return Err(invalid("invalid NetBird profile"));
    }
    serde_json::from_value::<Profile>(value["settings"].clone())
        .map_err(|_| invalid("invalid NetBird profile fields"))?
        .validate()
}

pub fn parse(input: &str) -> io::Result<Value> {
    let value =
        crate::profile::strict_json(input).map_err(|_| invalid("invalid NetBird profile JSON"))?;
    let profile = if value.get("protocol").is_some() {
        decoded_profile(&value)?
    } else {
        serde_json::from_value::<Profile>(value)
            .map_err(|_| invalid("invalid NetBird profile fields"))?
            .validate()?
    };
    Ok(json!({"protocol":"netbird","settings":profile}))
}
