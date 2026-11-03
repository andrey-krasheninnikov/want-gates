use crate::{invalid, read_message_with_timeout, write_message};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

pub fn is_native(protocol: &str) -> bool {
    matches!(protocol, "openvpn" | "forti")
}

pub const DEFAULT_SOCKET: &str = "/run/wgates-native/control.sock";

#[derive(Clone)]
pub struct Client {
    pub socket: PathBuf,
}
impl Client {
    pub fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_owned(),
        }
    }
    pub fn call(&self, mut request: Value) -> io::Result<Value> {
        if !cfg!(target_os = "linux") {
            return Err(invalid("native runtime requires Linux"));
        }
        request["api_version"] = json!(1);
        let mut stream = UnixStream::connect(&self.socket).map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "native runtime unavailable; start wgates-native.service and check socket access",
            )
        })?;
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
            let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            // SAFETY: getsockopt initializes the correctly sized credentials buffer on success.
            if unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    credentials.as_mut_ptr().cast(),
                    &mut size,
                )
            } != 0
            {
                return Err(invalid("cannot authenticate native runtime peer"));
            }
            // SAFETY: the successful getsockopt call initialized credentials.
            if unsafe { credentials.assume_init().uid } != 0 {
                return Err(invalid("native runtime peer must be root"));
            }
        }
        write_message(&mut stream, &request).map_err(transport_error)?;
        let response = read_message_with_timeout(
            &mut stream,
            if matches!(request["command"].as_str(), Some("state" | "list")) {
                std::time::Duration::from_millis(500)
            } else {
                std::time::Duration::from_secs(30)
            },
        )
        .map_err(transport_error)?;
        if response["api_version"] != 1 {
            return Err(invalid("incompatible native runtime protocol"));
        }
        if let Some(error) = response["error"].as_str() {
            return Err(invalid(error));
        }
        response
            .get("data")
            .cloned()
            .ok_or_else(|| invalid("invalid native runtime response"))
    }
}

fn transport_error(error: io::Error) -> io::Error {
    if matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    ) {
        io::Error::new(
            io::ErrorKind::NotConnected,
            "native runtime transport unavailable",
        )
    } else {
        error
    }
}
pub fn unavailable(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotConnected
}
fn unavailable_observation() -> Observation {
    Observation {
        authentication: "unavailable".into(),
        reason: "native_runtime_unavailable".into(),
        ..Default::default()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub id: String,
    pub generation: String,
    pub profile_digest: String,
    pub address: std::net::IpAddr,
    pub data_port: u16,
    pub probe_port: u16,
    pub password: String,
    pub probe_password: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub session: String,
    pub authentication: String,
    pub reason: String,
    pub dns: Option<String>,
    pub admitted: bool,
    pub resources_active: bool,
    pub expires_at: Option<u64>,
    pub remembered: bool,
}
impl Prepared {
    pub fn bridge_id(&self, diagnostic: bool) -> String {
        let key = if diagnostic {
            &self.probe_password
        } else {
            &self.password
        };
        format!(
            "{}-{}-{}-{}-{}",
            &key[..8],
            &key[8..12],
            &key[12..16],
            &key[16..20],
            &key[20..]
        )
    }
    pub fn outbound(&self, diagnostic: bool) -> Value {
        json!({"protocol":"vless","settings":{"address":self.address.to_string(),"port":if diagnostic{self.probe_port}else{self.data_port},"id":self.bridge_id(diagnostic),"encryption":"none"},"streamSettings":{"network":"raw","security":"none"}})
    }
}
pub type Generations = BTreeMap<String, Prepared>;
pub fn diagnostic_tag(connection: &crate::store::Connection) -> String {
    format!(
        "wgates-{}-{}",
        if is_native(&connection.protocol) {
            "diagnostic"
        } else {
            "out"
        },
        connection.id
    )
}

pub fn desired_digest(input: &crate::routing::Input) -> io::Result<String> {
    crate::routing::digest(&json!({"config":input.config,"profiles":input.profiles}))
}
pub fn observe(
    client: &Client,
    prepared: &Generations,
) -> io::Result<BTreeMap<String, Observation>> {
    observations(client, prepared, false)
}
pub fn health_observations(
    client: &Client,
    prepared: &Generations,
) -> io::Result<BTreeMap<String, Observation>> {
    match observations(client, prepared, true) {
        Err(error) if unavailable(&error) => Ok(prepared
            .keys()
            .map(|id| (id.clone(), unavailable_observation()))
            .collect()),
        result => result,
    }
}
fn observations(
    client: &Client,
    prepared: &Generations,
    allow_missing: bool,
) -> io::Result<BTreeMap<String, Observation>> {
    if prepared.is_empty() {
        return Ok(BTreeMap::new());
    }
    let values = client.call(json!({"command":"list"}))?;
    let values = values
        .as_array()
        .ok_or_else(|| invalid("invalid native inventory"))?;
    let mut result = BTreeMap::new();
    for (id, generation) in prepared {
        let Some(value) = values
            .iter()
            .find(|value| value["prepared"]["generation"] == generation.generation)
        else {
            if allow_missing {
                result.insert(id.clone(), unavailable_observation());
                continue;
            }
            return Err(invalid(
                "native generation is not prepared; preview and apply before continuing",
            ));
        };
        let actual: Prepared = serde_json::from_value(value["prepared"].clone())
            .map_err(|_| invalid("invalid native preparation response"))?;
        if crate::routing::digest(&actual)? != crate::routing::digest(generation)? {
            return Err(invalid(
                "native preparation changed; preview and apply before continuing",
            ));
        }
        let state: Observation = serde_json::from_value(value["observation"].clone())
            .map_err(|_| invalid("invalid native observation"))?;
        result.insert(id.clone(), state);
    }
    Ok(result)
}

pub fn effective(
    config: &crate::store::Config,
    observations: &BTreeMap<String, Observation>,
) -> crate::store::Config {
    let mut config = config.clone();
    for connection in &mut config.connections {
        if is_native(&connection.protocol) && connection.dns.is_none() {
            connection.dns = observations.get(&connection.id).and_then(|v| v.dns.clone());
        }
    }
    config
}
pub fn admit(
    client: &Client,
    prepared: &Generations,
    observations: &BTreeMap<String, Observation>,
    config: &crate::store::Config,
    matrix: &crate::routing::Matrix,
) -> io::Result<()> {
    for (id, generation) in prepared {
        let state = observations
            .get(id)
            .ok_or_else(|| invalid("native observation missing"))?;
        let admitted = state.authentication == "authenticated"
            && config.groups.iter().any(|g| {
                g.primary.as_ref() == Some(id)
                    && matrix
                        .get(&g.id)
                        .is_some_and(|m| m.values().any(|s| s == "verified"))
            });
        if admitted != state.admitted {
            client.call(json!({"command":"admit","generation":generation.generation,"session":state.session,"admitted":admitted}))?;
        }
    }
    Ok(())
}

pub fn release(client: &Client, prepared: &Prepared) -> io::Result<()> {
    let inventory = client.call(json!({"command":"list"}))?;
    let inventory = inventory
        .as_array()
        .ok_or_else(|| invalid("invalid native inventory"))?;
    if let Some(value) = inventory
        .iter()
        .find(|v| v["prepared"]["generation"] == prepared.generation)
    {
        let current: Prepared = serde_json::from_value(value["prepared"].clone())
            .map_err(|_| invalid("invalid native preparation response"))?;
        if crate::routing::digest(&current)? != crate::routing::digest(prepared)? {
            return Err(invalid(
                "native resource ownership changed; retain resources for inspection",
            ));
        }
        client.call(json!({"command":"release","generation":prepared.generation}))?;
        let inventory = client.call(json!({"command":"list"}))?;
        if inventory.as_array().is_none_or(|a| {
            a.iter()
                .any(|v| v["prepared"]["generation"] == prepared.generation)
        }) {
            return Err(invalid("native resource release could not be confirmed"));
        }
    }
    Ok(())
}

pub fn readiness(
    connection: &crate::store::Connection,
    observations: &BTreeMap<String, Observation>,
) -> Option<&'static str> {
    if !is_native(&connection.protocol) {
        return None;
    }
    match observations
        .get(&connection.id)
        .map(|o| o.authentication.as_str())
    {
        Some("authenticated") => None,
        Some(
            "credentials_required" | "challenge_required" | "browser_required" | "authenticating",
        ) => Some("native_authentication_required"),
        _ => Some("native_unavailable"),
    }
}
pub fn blocked(
    connection: &crate::store::Connection,
    reason: &str,
    health: bool,
) -> BTreeMap<String, String> {
    let mut result: BTreeMap<_, _> = crate::capability::ALL
        .into_iter()
        .map(|capability| {
            (
                capability.to_owned(),
                if crate::capability::permits(&connection.allowed_capabilities, capability) {
                    reason.to_owned()
                } else {
                    "configured_limit".into()
                },
            )
        })
        .collect();
    result.insert("dns".into(), reason.into());
    if health {
        result.insert("target".into(), reason.into());
    }
    result
}
pub fn verification_context(
    prepared: &Generations,
    observations: &BTreeMap<String, Observation>,
    config: &crate::store::Config,
    id: &str,
) -> io::Result<Option<String>> {
    let (Some(prepared), Some(observation), Some(connection)) = (
        prepared.get(id),
        observations.get(id),
        config.connections.iter().find(|c| c.id == id),
    ) else {
        return Ok(None);
    };
    crate::routing::digest(&json!({"generation":prepared.generation,"session":observation.session,"dns":connection.dns.as_ref().or(observation.dns.as_ref())})).map(Some)
}
