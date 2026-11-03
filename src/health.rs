use crate::{capability, invalid, policy::domain_name, store::Config};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Healthcheck {
    pub target: String,
    pub required_capabilities: Vec<String>,
    #[serde(default = "interval")]
    pub interval_seconds: u64,
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "failures")]
    pub failure_threshold: u64,
    #[serde(default = "successes")]
    pub recovery_threshold: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect_hex: Option<String>,
}
fn interval() -> u64 {
    30
}
fn timeout() -> u64 {
    5
}
fn failures() -> u64 {
    3
}
fn successes() -> u64 {
    5
}
impl Healthcheck {
    pub fn tcp_exchange(&self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        fn decode(value: &str) -> io::Result<Vec<u8>> {
            if value.len() > 2048
                || !value.len().is_multiple_of(2)
                || !value.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(invalid(
                    "TCP messages require even hexadecimal strings up to 1024 bytes",
                ));
            }
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|bytes| {
                    u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16)
                        .map_err(|_| invalid("invalid TCP hexadecimal message"))
                })
                .collect()
        }
        let expected = decode(self.expect_hex.as_deref().ok_or_else(|| {
            invalid("TCP healthcheck requires expect_hex to verify the resource response")
        })?)?;
        if expected.is_empty() {
            return Err(invalid("TCP expect_hex must be nonempty"));
        }
        Ok((decode(self.send_hex.as_deref().unwrap_or(""))?, expected))
    }
    pub fn validate(&self) -> io::Result<()> {
        capability::validate(&self.required_capabilities)?;
        if self.required_capabilities.is_empty()
            || !(1..=86400).contains(&self.interval_seconds)
            || !(1..=60).contains(&self.timeout_seconds)
            || self.timeout_seconds > self.interval_seconds
            || !(1..=1000).contains(&self.failure_threshold)
            || !(1..=1000).contains(&self.recovery_threshold)
        {
            return Err(invalid(
                "invalid healthcheck capabilities, interval, timeout or thresholds",
            ));
        }
        let url =
            url::Url::parse(&self.target).map_err(|_| invalid("invalid healthcheck target"))?;
        if !matches!(url.scheme(), "tcp" | "http" | "https")
            || self.target.len() > 2048
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port_or_known_default().is_none_or(|p| p == 0)
            || self
                .expected_status
                .is_some_and(|s| !(200..=599).contains(&s))
            || (url.scheme() == "tcp"
                && (self.expected_status.is_some() || !matches!(url.path(), "" | "/")))
            || (self.ca_pem.is_some() && url.scheme() != "https")
        {
            return Err(invalid(
                "healthcheck requires TCP with a port, HTTP or HTTPS without credentials, query or fragment",
            ));
        }
        if url.scheme() == "tcp" {
            self.tcp_exchange()?;
        } else if self.send_hex.is_some() || self.expect_hex.is_some() {
            return Err(invalid("send_hex and expect_hex require a TCP target"));
        }
        let host = url
            .host_str()
            .ok_or_else(|| invalid("healthcheck requires a host"))?
            .trim_matches(['[', ']']);
        match host.parse::<std::net::IpAddr>() {
            Ok(ip)
                if !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !matches!(ip,std::net::IpAddr::V6(a) if a.to_ipv4_mapped().is_some()) => {}
            Ok(_) => return Err(invalid("healthcheck requires a valid unicast host")),
            Err(_) => {
                domain_name(host)?;
            }
        }
        if let Some(pem) = &self.ca_pem {
            certificates(pem)?;
        }
        Ok(())
    }
}
pub fn certificates(pem: &str) -> io::Result<Vec<ureq::tls::Certificate<'static>>> {
    if pem.len() > 64 * 1024 || pem.contains("PRIVATE KEY") {
        return Err(invalid(
            "healthcheck CA requires public certificates up to 64 KiB",
        ));
    }
    let mut certificates = Vec::new();
    for item in ureq::tls::parse_pem(pem.as_bytes()) {
        match item {
            Ok(ureq::tls::PemItem::Certificate(c)) => certificates.push(c),
            _ => return Err(invalid("invalid healthcheck CA certificate")),
        }
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in &certificates {
        roots
            .add(rustls::pki_types::CertificateDer::from(certificate.der()))
            .map_err(|_| invalid("invalid healthcheck CA certificate"))?;
    }
    if certificates.is_empty() {
        return Err(invalid("healthcheck CA requires PEM certificates"));
    }
    Ok(certificates)
}
pub fn validate_groups(config: &Config) -> io::Result<()> {
    for group in &config.groups {
        let mut seen = BTreeSet::new();
        for id in &group.fallbacks {
            if group.primary.as_ref() == Some(id)
                || !seen.insert(id)
                || !config
                    .connections
                    .iter()
                    .any(|c| &c.id == id && c.group_id == group.id)
            {
                return Err(invalid(
                    "fallbacks must be distinct connections in the same group, excluding primary",
                ));
            }
        }
        if let Some(check) = &group.healthcheck {
            check.validate()?;
            if group.primary.is_none() {
                return Err(invalid("healthcheck requires a primary"));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub successes: u64,
    pub failures: u64,
    pub available: bool,
    pub was_down: bool,
    pub fresh: bool,
    pub observed_at: u64,
    pub reason: String,
    pub results: std::collections::BTreeMap<String, String>,
    pub admitted: std::collections::BTreeMap<String, String>,
}
impl Observation {
    pub fn record(
        &mut self,
        results: std::collections::BTreeMap<String, String>,
        policy: &Healthcheck,
    ) {
        self.fresh = true;
        self.observed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.reason = results
            .get("health")
            .cloned()
            .unwrap_or_else(|| "unknown".into());
        if self.reason == "verified" {
            for capability in capability::ALL.into_iter().chain(["dns"]) {
                if results.get(capability).is_some_and(|r| r == "verified") {
                    self.admitted.insert(capability.into(), "verified".into());
                }
            }
            self.failures = 0;
            self.successes = self
                .successes
                .saturating_add(1)
                .min(policy.recovery_threshold);
            if !self.was_down || self.successes >= policy.recovery_threshold {
                self.available = true;
            }
        } else {
            self.successes = 0;
            self.failures = self
                .failures
                .saturating_add(1)
                .min(policy.failure_threshold);
            if self.failures >= policy.failure_threshold {
                self.available = false;
                self.was_down = true;
            }
        }
        self.results = results;
    }
    pub fn describe(&self) -> serde_json::Value {
        serde_json::json!({"state":if !self.fresh{"unknown"}else if self.available{if self.failures>0{"suspect"}else{"healthy"}}else if self.successes>0{"recovering"}else if self.was_down{"unhealthy"}else{"checking"},"eligible":self.available&&self.fresh,"reason":self.reason,"successes":self.successes,"failures":self.failures,"observed_at":self.observed_at,"results":self.results})
    }
}
