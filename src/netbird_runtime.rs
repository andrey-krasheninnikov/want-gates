use super::{
    Authentication, Child, Command, Credentials, Endpoint, Instant, Record, Stdio, command,
    executable, namespace_child, ns, private_text, random_id, secure_directory,
};
use crate::netbird::{Mode, Profile, decoded_profile, https_url, network_id};
use crate::{invalid, openvpn_auth::now, policy::Network, wireguard::unicast};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(super) const CURL: &str = "/usr/bin/curl";
const LOGIN_SECONDS: u64 = 300;

pub(super) type Hosts = BTreeMap<String, BTreeSet<IpAddr>>;

fn allowed_endpoints(profile: &Profile, hosts: &Hosts) -> io::Result<Vec<Endpoint>> {
    let configured = profile.endpoints()?;
    let expected: BTreeSet<_> = configured.iter().map(|e| e.host.as_str()).collect();
    if hosts.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(invalid("invalid retained NetBird control hosts"));
    }
    let mut pins = BTreeSet::new();
    for endpoint in configured {
        let addresses = &hosts[&endpoint.host];
        if addresses.is_empty()
            || addresses.iter().any(|ip| !unicast(*ip))
            || endpoint
                .host
                .parse::<IpAddr>()
                .is_ok_and(|ip| addresses != &BTreeSet::from([ip]))
        {
            return Err(invalid("invalid NetBird control endpoint addresses"));
        }
        for &ip in addresses {
            pins.insert((ip, endpoint.port, endpoint.transport.clone()));
        }
    }
    if pins.len() > 32 {
        return Err(invalid("NetBird control endpoint address limit exceeded"));
    }
    Ok(pins
        .into_iter()
        .map(|(address, port, protocol)| Endpoint {
            address,
            port,
            protocol,
        })
        .collect())
}

pub(super) fn resolve(profile: &Profile) -> io::Result<(Vec<Endpoint>, Hosts)> {
    let mut hosts = Hosts::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    for endpoint in profile.endpoints()? {
        if hosts.contains_key(&endpoint.host) {
            continue;
        }
        if Instant::now() >= deadline {
            return Err(invalid("NetBird control endpoint resolution timed out"));
        }
        let ips = if let Ok(ip) = endpoint.host.parse() {
            BTreeSet::from([ip])
        } else {
            command(
                "/usr/bin/getent",
                &["-s", "files", "ahosts", &endpoint.host],
            )
            .or_else(|_| {
                command(
                    "/usr/bin/getent",
                    &["ahosts", &format!("{}.", endpoint.host)],
                )
            })
            .map_err(|_| invalid("NetBird control endpoint resolution failed"))?
            .lines()
            .filter_map(|line| line.split_whitespace().next()?.parse().ok())
            .take(33)
            .collect()
        };
        hosts.insert(endpoint.host, ips);
    }
    Ok((allowed_endpoints(profile, &hosts)?, hosts))
}

pub(super) fn validate(record: &Record) -> io::Result<()> {
    let profile = decoded_profile(&record.profile)?;
    let pinned = allowed_endpoints(&profile, &record.netbird_hosts)?;
    if pinned != record.endpoints {
        return Err(invalid(
            "NetBird retained control endpoints differ from profile",
        ));
    }
    Ok(())
}

pub(super) fn check(binary: &Path) -> io::Result<String> {
    executable(Path::new(CURL))?;
    let binary = executable(binary)?;
    let path = binary
        .to_str()
        .ok_or_else(|| invalid("invalid NetBird executable path"))?;
    let version = command(path, &["version"])?;
    if version.trim() != "0.83.2" {
        return Err(invalid("native runtime requires NetBird 0.83.2"));
    }
    if !Path::new("/dev/net/tun").exists() {
        return Err(invalid(
            "TUN unavailable; provide /dev/net/tun to the native runtime",
        ));
    }
    Ok(version.trim().into())
}

pub(super) fn state_directory(root: &Path, record: &Record) -> PathBuf {
    root.join(format!("netbird-{}", record.prepared.generation))
}

pub(super) fn remove_state(root: &Path, record: &Record) -> io::Result<()> {
    remove_directory(&state_directory(root, record))
}

pub(super) fn remove_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            secure_directory(path, 0o700, 0o077)?;
            fs::remove_dir_all(path)?;
            fs::File::open(path.parent().unwrap())?.sync_all()
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) struct ProcessFiles<'a> {
    pub runtime: &'a Path,
    pub state: &'a Path,
}

impl ProcessFiles<'_> {
    pub fn mounts(&self) -> io::Result<Vec<(CString, CString)>> {
        let mut mounts = Vec::new();
        for (name, path) in [("hosts", "/etc/hosts"), ("resolv.conf", "/etc/resolv.conf")] {
            let target = fs::canonicalize(path)?;
            mounts.push((
                CString::new(self.runtime.join(name).as_os_str().as_encoded_bytes())
                    .map_err(|_| invalid("invalid NetBird mount path"))?,
                CString::new(target.as_os_str().as_encoded_bytes())
                    .map_err(|_| invalid("invalid NetBird mount target"))?,
            ));
        }
        if Path::new("/etc/iproute2").is_dir() {
            mounts.push((
                CString::new(self.runtime.join("iproute2").as_os_str().as_encoded_bytes())
                    .map_err(|_| invalid("invalid NetBird mount path"))?,
                c"/etc/iproute2".into(),
            ));
        }
        Ok(mounts)
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Configure,
    Login { setup_key: bool },
    Wait,
    Up,
    Status,
    Networks { revision: u64, readback: bool },
    Select { revision: u64 },
}

impl Operation {
    fn method(self) -> &'static str {
        match self {
            Self::Configure => "SetConfig",
            Self::Login { .. } => "Login",
            Self::Wait => "WaitSSOLogin",
            Self::Up => "Up",
            Self::Status => "Status",
            Self::Networks { .. } => "ListNetworks",
            Self::Select { .. } => "SelectNetworks",
        }
    }
}

struct Request {
    child: Child,
    output: Vec<u8>,
    operation: Operation,
}

impl Request {
    fn start(socket: &Path, operation: Operation, body: &Value) -> io::Result<Self> {
        let timeout = match operation {
            Operation::Wait => "300",
            Operation::Login { .. } => "15",
            _ => "3",
        };
        let mut request = Self {
            operation,
            output: Vec::new(),
            child: Command::new(CURL)
                .env_clear()
                .args([
                    "--disable",
                    "--silent",
                    "--fail",
                    "--noproxy",
                    "*",
                    "--max-time",
                    timeout,
                ])
                .arg("--unix-socket")
                .arg(socket)
                .args([
                    "--header",
                    "Content-Type: application/json",
                    "--data-binary",
                    "@-",
                ])
                .arg(format!(
                    "http://localhost/daemon.DaemonService/{}",
                    operation.method()
                ))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| invalid("NetBird control request could not be started"))?,
        };
        request
            .child
            .stdin
            .take()
            .unwrap()
            .write_all(body.to_string().as_bytes())
            .map_err(|_| invalid("NetBird control request could not be sent"))?;
        let output = request.child.stdout.as_ref().unwrap();
        // SAFETY: this FD is a live pipe owned by the request.
        if unsafe { libc::fcntl(output.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            return Err(invalid("NetBird control output could not be configured"));
        }
        Ok(request)
    }

    fn poll(&mut self) -> io::Result<Option<Option<Value>>> {
        let status = self.child.try_wait()?;
        let output = self.child.stdout.as_mut().unwrap();
        let mut buf = [0; 8192];
        loop {
            match output.read(&mut buf) {
                Ok(0) => break,
                Ok(n) if self.output.len() + n <= 1024 * 1024 => {
                    self.output.extend_from_slice(&buf[..n]);
                }
                Ok(_) => return Err(invalid("NetBird control response exceeds its limit")),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return Err(invalid("NetBird control response is unreadable")),
            }
        }
        Ok(status.map(|status| {
            status
                .success()
                .then(|| {
                    serde_json::from_slice::<Value>(&self.output)
                        .ok()
                        .filter(Value::is_object)
                })
                .flatten()
        }))
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginInput {
    setup_key: String,
}

#[derive(Deserialize)]
struct Route {
    #[serde(rename = "ID")]
    id: String,
    range: String,
    #[serde(default)]
    selected: bool,
}

fn route_selection(profile: &Profile, response: &Value) -> io::Result<(Vec<String>, bool)> {
    let routes: Vec<Route> =
        serde_json::from_value(response.get("routes").cloned().unwrap_or(json!([])))
            .map_err(|_| invalid("invalid NetBird network inventory"))?;
    let mut target_found = profile.mode == Mode::Private;
    let mut desired = BTreeSet::new();
    let mut selected = BTreeSet::new();
    for route in routes {
        if !network_id(&route.id) {
            return Err(invalid("invalid NetBird network ID"));
        }
        let mut is_exit = false;
        for prefix in route.range.split(',') {
            is_exit |= Network::parse(prefix.trim())
                .map_err(|_| invalid("unsupported NetBird network range"))?
                .prefix
                == 0;
        }
        if is_exit && profile.exit_network_id.as_ref() == Some(&route.id) {
            target_found = true;
            desired.insert(route.id.clone());
        } else if !is_exit {
            desired.insert(route.id.clone());
        }
        if route.selected {
            selected.insert(route.id);
        }
    }
    if !target_found {
        return Err(invalid("configured NetBird exit node is unavailable"));
    }
    let matches = selected == desired;
    Ok((desired.into_iter().collect(), matches))
}

pub(super) struct Session {
    socket: PathBuf,
    state: PathBuf,
    profile: Profile,
    hostname: String,
    port: u16,
    startup: Instant,
    next_status: Instant,
    request: Option<Request>,
    configured: bool,
    revision: Option<u64>,
    explicit_selection: bool,
    user_code: Option<String>,
}

impl Session {
    pub fn start(
        record: &Record,
        data_root: &Path,
        runtime: &Path,
        binary: &Path,
        bridge_uid: u32,
    ) -> io::Result<(Self, Child)> {
        let profile = decoded_profile(&record.profile)?;
        let state = state_directory(data_root, record);
        secure_directory(&state, 0o700, 0o077)?;
        let runtime = runtime.join("netbird");
        secure_directory(&runtime, 0o700, 0o077)?;
        let mut hosts = "127.0.0.1 localhost\n::1 localhost\n".to_owned();
        for (host, addresses) in &record.netbird_hosts {
            if host.parse::<IpAddr>().is_err() {
                for ip in addresses {
                    hosts.push_str(&format!("{ip} {host}\n"));
                }
            }
        }
        private_text(&runtime.join("hosts"), &hosts)?;
        private_text(
            &runtime.join("resolv.conf"),
            "nameserver 127.0.0.1\noptions attempts:1 timeout:1\n",
        )?;
        secure_directory(&runtime.join("iproute2"), 0o700, 0o077)?;
        private_text(&runtime.join("iproute2/rt_tables"), "")?;
        if profile.mode == Mode::Private {
            let uid = format!("{bridge_uid}-{bridge_uid}");
            // NetBird v0.83.2 uses priority 105 for main and 110 for table 7120.
            for family in ["-4", "-6"] {
                for (priority, table) in [("100", "main"), ("101", "7120")] {
                    ns(
                        record,
                        &[
                            family,
                            "rule",
                            "add",
                            "priority",
                            priority,
                            "uidrange",
                            &uid,
                            "lookup",
                            table,
                            "suppress_prefixlength",
                            "0",
                        ],
                    )?;
                }
                ns(
                    record,
                    &[
                        family,
                        "rule",
                        "add",
                        "priority",
                        "102",
                        "uidrange",
                        &uid,
                        "unreachable",
                    ],
                )?;
            }
        }
        let socket = runtime.join("json.sock");
        let grpc_socket = runtime.join("grpc.sock");
        if socket.as_os_str().as_encoded_bytes().len() >= 108
            || grpc_socket.as_os_str().as_encoded_bytes().len() >= 108
        {
            return Err(invalid("NetBird Unix socket path is too long"));
        }
        let config = state.join("config.json");
        let child = namespace_child(
            record,
            &executable(binary)?,
            &[
                "--daemon-addr",
                &format!("unix://{}", grpc_socket.display()),
                "--config",
                config
                    .to_str()
                    .ok_or_else(|| invalid("invalid NetBird state path"))?,
                "--log-file",
                "console",
                "--log-level",
                "error",
                "service",
                "run",
                "--enable-json-socket",
                "--json-socket",
                &format!("unix://{}", socket.display()),
            ],
            Stdio::null(),
            None,
            Some(super::NativeFiles::Netbird(ProcessFiles {
                runtime: &runtime,
                state: &state,
            })),
        )?;
        let octets = record.host.octets();
        let port = 40000 + u16::from(octets[2]) * 64 + u16::from(octets[3]) / 4;
        let hostname = format!(
            "wgates-{}-{}",
            record.prepared.id,
            &record.prepared.generation[..8]
        );
        let start = Instant::now();
        Ok((
            Self {
                socket,
                state,
                profile,
                hostname,
                port,
                startup: start + Duration::from_secs(10),
                next_status: start,
                request: None,
                configured: false,
                revision: None,
                explicit_selection: false,
                user_code: None,
            },
            child,
        ))
    }

    fn send(&mut self, operation: Operation, value: Value) -> io::Result<()> {
        self.request = Some(Request::start(&self.socket, operation, &value)?);
        Ok(())
    }

    fn marker(&self) -> PathBuf {
        self.state.join("enrolled")
    }

    pub fn login(
        &mut self,
        auth: &mut Authentication,
        input: Option<&Value>,
        remember: bool,
    ) -> io::Result<Value> {
        if remember {
            return Err(invalid(
                "NetBird setup keys are used once; --remember is unsupported",
            ));
        }
        let input: Option<LoginInput> = input
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()
            .map_err(|_| invalid("NetBird login accepts only a setup_key field"))?;
        if let Some(input) = &input
            && (input.setup_key.is_empty()
                || input.setup_key.len() > 256
                || !input
                    .setup_key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        {
            return Err(invalid("invalid NetBird setup key format"));
        }
        if auth.state == "browser_required" {
            if input.is_some() {
                return Err(invalid("NetBird browser login is pending"));
            }
            let mut action = auth.action();
            action["user_code"] = json!(self.user_code);
            return Ok(action);
        }
        if auth.state == "authenticated" || auth.state == "authenticating" {
            if input.is_some() {
                return Err(invalid("NetBird connection already has an active login"));
            }
            return Ok(auth.describe());
        }
        if !self.configured {
            return Err(invalid(
                "NetBird client is starting; retry login when ready",
            ));
        }
        self.request = None;
        auth.session = random_id()?;
        auth.submitted();
        self.revision = None;
        self.explicit_selection = false;
        let mut request = json!({
            "isUnixDesktopClient": false,
            "hostname": self.hostname,
        });
        let setup_key = input.is_some();
        if let Some(input) = input {
            request["setupKey"] = json!(input.setup_key);
        }
        self.send(Operation::Login { setup_key }, request)?;
        Ok(auth.describe())
    }

    fn connect(&mut self, auth: &mut Authentication) -> io::Result<()> {
        self.user_code = None;
        auth.submitted();
        self.send(Operation::Up, json!({"async":true}))
    }

    fn connected(&mut self, auth: &mut Authentication, revision: u64) {
        auth.remembered = true;
        auth.authenticated("netbird_connected");
        self.revision = Some(revision);
    }

    fn enrollment_finished(&mut self, auth: &mut Authentication) -> io::Result<()> {
        if !self.marker().exists() {
            private_text(&self.marker(), "")?;
            fs::File::open(&self.state)?.sync_all()?;
        }
        self.connect(auth)
    }

    pub fn poll(&mut self, auth: &mut Authentication) -> io::Result<()> {
        if auth.state == "browser_required" && auth.expire() {
            self.request = None;
            self.user_code = None;
            return Ok(());
        }
        if let Some(request) = self.request.as_mut() {
            let Some(response) = request.poll()? else {
                return Ok(());
            };
            let operation = request.operation;
            self.request = None;
            return self.receive(auth, operation, response);
        }
        if !self.configured {
            let available = fs::symlink_metadata(&self.socket)
                .is_ok_and(|m| m.uid() == 0 && m.file_type().is_socket());
            if available {
                return self.send(
                    Operation::Configure,
                    json!({
                        "managementUrl": self.profile.management_url,
                        "interfaceName": "wgates-tun",
                        "wireguardPort": self.port,
                        "disableAutoConnect": true,
                        "disableDns": true,
                        "disableServerRoutes": true,
                        "serverSSHAllowed": false,
                        "enableLocalMetrics": false,
                        "remoteJobsAllowed": false
                    }),
                );
            }
            if Instant::now() >= self.startup {
                return Err(invalid("NetBird private socket did not become ready"));
            }
            return Ok(());
        }
        if Instant::now() >= self.next_status
            && !matches!(
                auth.state.as_str(),
                "credentials_required" | "expired" | "failed"
            )
        {
            self.next_status = Instant::now() + Duration::from_secs(1);
            self.send(Operation::Status, json!({"getFullPeerStatus":true}))?;
        }
        Ok(())
    }

    fn receive(
        &mut self,
        auth: &mut Authentication,
        operation: Operation,
        response: Option<Value>,
    ) -> io::Result<()> {
        let Some(value) = response else {
            match operation {
                Operation::Configure => return Err(invalid("NetBird configuration was refused")),
                Operation::Wait | Operation::Login { .. } => {
                    self.user_code = None;
                    auth.fail("authentication_netbird_login_failed");
                }
                _ => self.unavailable(auth, "netbird_control_unavailable")?,
            }
            return Ok(());
        };
        match operation {
            Operation::Configure => {
                self.configured = true;
                if self.marker().exists() {
                    self.connect(auth)?;
                } else {
                    auth.state = "credentials_required".into();
                    auth.reason = "netbird_enrollment_required".into();
                }
            }
            Operation::Login { setup_key } => {
                if value["needsSSOLogin"] == true {
                    if setup_key {
                        return Err(invalid("NetBird did not accept setup key enrollment"));
                    }
                    let code = value["userCode"]
                        .as_str()
                        .filter(|s| {
                            !s.is_empty()
                                && s.len() <= 128
                                && s.bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                        })
                        .ok_or_else(|| invalid("invalid NetBird device code"))?;
                    let uri = value["verificationURI"]
                        .as_str()
                        .filter(|s| s.len() < 4096)
                        .ok_or_else(|| invalid("invalid NetBird verification URL"))?;
                    let uri = https_url(uri)?;
                    auth.require(
                        "web",
                        "Open the URL and enter the NetBird device code",
                        Some(uri.to_string()),
                        code.into(),
                    )?;
                    auth.expires_at = Some(now() + LOGIN_SECONDS);
                    self.user_code = Some(code.into());
                    self.send(
                        Operation::Wait,
                        json!({"userCode": code, "hostname": self.hostname}),
                    )?;
                } else {
                    self.enrollment_finished(auth)?;
                }
            }
            Operation::Wait => self.enrollment_finished(auth)?,
            Operation::Up => {
                auth.state = "connecting".into();
                auth.reason = "netbird_connecting".into();
                self.next_status = Instant::now();
            }
            Operation::Status => self.status(auth, &value)?,
            Operation::Networks { revision, readback } => {
                let (ids, matches) = match route_selection(&self.profile, &value) {
                    Ok(selection) => selection,
                    Err(_) => return self.unavailable(auth, "netbird_routes_unavailable"),
                };
                if matches && (self.explicit_selection || readback) {
                    self.explicit_selection = true;
                    self.connected(auth, revision);
                } else if readback {
                    self.unavailable(auth, "netbird_route_selection_unconfirmed")?;
                } else {
                    self.send(Operation::Select { revision }, json!({"networkIDs":ids}))?;
                }
            }
            Operation::Select { revision } => self.send(
                Operation::Networks {
                    revision,
                    readback: true,
                },
                json!({}),
            )?,
        }
        Ok(())
    }

    fn unavailable(&mut self, auth: &mut Authentication, reason: &str) -> io::Result<()> {
        if auth.state == "authenticated" {
            auth.session = random_id()?;
        }
        self.revision = None;
        self.explicit_selection = false;
        auth.fail(reason);
        Ok(())
    }

    fn status(&mut self, auth: &mut Authentication, value: &Value) -> io::Result<()> {
        match value["status"].as_str() {
            Some("Connected")
                if value.pointer("/fullStatus/managementState/connected") == Some(&json!(true)) =>
            {
                let revision = value
                    .pointer("/fullStatus/networksRevision")
                    .and_then(|v| {
                        v.as_str()
                            .and_then(|s| s.parse().ok())
                            .or_else(|| v.as_u64())
                    })
                    .unwrap_or(0);
                if self.revision != Some(revision) {
                    if auth.state == "authenticated" {
                        auth.session = random_id()?;
                    }
                    self.revision = None;
                    auth.state = "connecting".into();
                    auth.reason = "netbird_confirming_routes".into();
                    self.send(
                        Operation::Networks {
                            revision,
                            readback: false,
                        },
                        json!({}),
                    )?;
                }
            }
            Some("SessionExpired") => {
                self.unavailable(auth, "netbird_session_ended")?;
                auth.fail("authentication_expired");
            }
            Some("NeedsLogin" | "LoginFailed") => {
                self.unavailable(auth, "netbird_login_required")?;
                auth.state = "credentials_required".into();
            }
            _ => self.unavailable(auth, "netbird_disconnected")?,
        }
        Ok(())
    }
}

pub(super) fn new_auth() -> io::Result<Authentication> {
    Authentication::new(Credentials::default(), false)
}
