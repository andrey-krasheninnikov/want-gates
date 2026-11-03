use crate::{invalid, profile::strict_json};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{self, Read};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

pub const MAX_PANEL: usize = 16 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub url: String,
    pub token: String,
}
impl Settings {
    pub fn validate(&self) -> io::Result<()> {
        let url = url::Url::parse(&self.url).map_err(|_| invalid("invalid panel URL"))?;
        let local = match url.host() {
            Some(url::Host::Ipv4(a)) => a.is_loopback(),
            Some(url::Host::Ipv6(a)) => a.is_loopback(),
            _ => false,
        };
        if !(url.scheme() == "https" || (url.scheme() == "http" && local))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || self.url.len() > 4096
            || self.token.is_empty()
            || self.token.len() > 4096
            || !self.token.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(invalid(
                "panel requires HTTPS or literal loopback HTTP, a base URL without credentials/query/fragment, and a private Bearer token",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub template: Value,
    pub outbound_test_url: String,
    pub inbounds: Vec<Value>,
}
pub struct Client {
    settings: Settings,
    http: ureq::Agent,
    stopping: Arc<AtomicBool>,
    deadline: Instant,
}
impl Client {
    pub fn new(settings: Settings, stopping: Arc<AtomicBool>) -> io::Result<Self> {
        settings.validate()?;
        let http = ureq::Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(5)))
            .build()
            .into();
        Ok(Self {
            settings,
            http,
            stopping,
            deadline: Instant::now() + Duration::from_secs(300),
        })
    }
    pub fn until(&self, deadline: Instant) -> Self {
        Self {
            settings: self.settings.clone(),
            http: self.http.clone(),
            stopping: self.stopping.clone(),
            deadline: self.deadline.min(deadline),
        }
    }
    pub fn check(&self) -> io::Result<()> {
        if self.stopping.load(Ordering::Relaxed) {
            return Err(io::Error::other(
                "routing interrupted; inspect state before recovery",
            ));
        }
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "routing operation exceeded 300 seconds; inspect state",
            ));
        }
        Ok(())
    }
    pub fn cancelled(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
    }
    fn request(&self, path: &str, form: Option<&[(&str, &str)]>) -> io::Result<Value> {
        self.check()?;
        let url = format!(
            "{}/panel/api/{path}",
            self.settings.url.trim_end_matches('/')
        );
        let authorization = format!("Bearer {}", self.settings.token);
        let timeout = self
            .deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(5));
        let response = if let Some(form) = form {
            self.http
                .post(&url)
                .header("Authorization", &authorization)
                .config()
                .timeout_global(Some(timeout))
                .build()
                .send_form(form.iter().copied())
        } else {
            self.http
                .get(&url)
                .header("Authorization", &authorization)
                .config()
                .timeout_global(Some(timeout))
                .build()
                .call()
        };
        let mut response = response.map_err(|error| io::Error::new(
            if matches!(error,ureq::Error::Timeout(_)) || Instant::now()>=self.deadline {io::ErrorKind::TimedOut}else{io::ErrorKind::Other},
            "panel request failed; check access, version, TLS and connectivity; no automatic retry"))?;
        if response.status().as_u16() != 200 {
            return Err(io::Error::other("unexpected panel HTTP status"));
        }
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(MAX_PANEL as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                io::Error::new(
                    if Instant::now() >= self.deadline
                        || error.kind() == io::ErrorKind::TimedOut
                        || error
                            .get_ref()
                            .and_then(|e| e.downcast_ref::<ureq::Error>())
                            .is_some_and(|e| matches!(e, ureq::Error::Timeout(_)))
                    {
                        io::ErrorKind::TimedOut
                    } else {
                        io::ErrorKind::Other
                    },
                    "cannot read panel response",
                )
            })?;
        self.check()?;
        if bytes.len() > MAX_PANEL {
            return Err(invalid("panel response exceeds 16 MiB"));
        }
        let body =
            std::str::from_utf8(&bytes).map_err(|_| invalid("invalid panel response encoding"))?;
        let result = strict_json(body).map_err(|_| invalid("invalid panel JSON response"))?;
        if result["success"].as_bool() != Some(true) {
            return Err(io::Error::other(
                "panel rejected the operation; inspect saved and running state",
            ));
        }
        Ok(result["obj"].clone())
    }
    pub fn status(&self) -> io::Result<Value> {
        let value = self.request("server/status", None)?;
        if value["panelVersion"]
            .as_str()
            .map(|s| s.trim_start_matches('v'))
            != Some("3.8.5")
            || value["xray"]["version"]
                .as_str()
                .map(|s| s.trim_start_matches('v'))
                != Some("26.9.9")
        {
            return Err(invalid(
                "incompatible deployment; require 3x-ui 3.8.5 and Xray 26.9.9",
            ));
        }
        Ok(
            json!({"panel_version":"3.8.5","xray_version":"26.9.9","running":value["xray"]["state"]=="running",
            "runtime_error": value["xray"]["errorMsg"].as_str().is_none_or(|s|!s.is_empty())}),
        )
    }
    pub fn running(&self) -> io::Result<Value> {
        let status = self.status()?;
        if status["running"] != true || status["runtime_error"] != false {
            return Err(io::Error::other(
                "Xray is stopped or has a pending runtime error; reconcile the panel first",
            ));
        }
        Ok(status)
    }
    pub fn read(&self) -> io::Result<Snapshot> {
        let value = self.request("xray/", Some(&[]))?;
        let value = if let Some(s) = value.as_str() {
            strict_json(s).map_err(|_| invalid("invalid panel settings envelope"))?
        } else {
            value
        };
        let template = value
            .get("xraySetting")
            .filter(|v| v.is_object())
            .ok_or_else(|| invalid("panel API returned no Xray template"))?
            .clone();
        let outbound_test_url = value["outboundTestUrl"]
            .as_str()
            .ok_or_else(|| invalid("panel API returned no outbound test URL"))?
            .to_owned();
        let inbounds = self.request("inbounds/list", None)?;
        let inbounds = inbounds
            .as_array()
            .ok_or_else(|| invalid("invalid panel inbound list"))?;
        let mut projection = Vec::new();
        for inbound in inbounds {
            let mut fields = serde_json::Map::new();
            for key in [
                "id",
                "enable",
                "protocol",
                "tag",
                "listen",
                "port",
                "settings",
                "streamSettings",
                "sniffing",
                "nodeId",
            ] {
                fields.insert(key.to_owned(), inbound[key].clone());
            }
            if !fields["id"].is_number()
                || !fields["enable"].is_boolean()
                || !fields["protocol"].is_string()
                || !fields["tag"].is_string()
            {
                return Err(invalid("invalid panel inbound metadata"));
            }
            projection.push(Value::Object(fields));
        }
        projection.sort_by_key(|v| v["id"].as_i64());
        Ok(Snapshot {
            template,
            outbound_test_url,
            inbounds: projection,
        })
    }
    pub fn update(&self, snapshot: &Snapshot) -> io::Result<()> {
        let template = serde_json::to_string(&snapshot.template)?;
        let fields = [
            ("xraySetting", template.as_str()),
            ("outboundTestUrl", snapshot.outbound_test_url.as_str()),
        ];
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        if encoded.len() > 10 * 1024 * 1024 {
            return Err(invalid("encoded panel update exceeds its 10 MiB limit"));
        }
        self.request("xray/update", Some(&fields))?;
        Ok(())
    }
    pub fn route(&self, inbound: &str, ip: &str, network: &str, port: u16) -> io::Result<String> {
        self.route_context(inbound, ip, None, None, network, port)
    }
    pub fn route_context(
        &self,
        inbound: &str,
        ip: &str,
        domain: Option<&str>,
        email: Option<&str>,
        network: &str,
        port: u16,
    ) -> io::Result<String> {
        let port = port.to_string();
        let result = self.request(
            "xray/routeTest",
            Some(&[
                ("inboundTag", inbound),
                ("ip", ip),
                ("domain", domain.unwrap_or("")),
                ("email", email.unwrap_or("")),
                ("network", network),
                ("port", &port),
            ]),
        )?;
        result["outboundTag"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("invalid runtime route-test response"))
    }
}
