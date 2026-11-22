use crate::forti::{decoded_profile, option};
use crate::native_runtime::{Record, namespace_child, private_text};
use crate::openvpn::Profile;
use crate::openvpn_auth::{Authentication, now};
use crate::{OwnedSocket, invalid, secure_directory, store::random_id};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt, chown};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const PASSWORD_LIMIT: usize = 256;
const OTP_LIMIT: usize = 64;
const SAML_CALLBACK_SECONDS: u64 = 50;

fn write_input(input: &mut ChildStdin, value: &str, limit: usize) -> io::Result<()> {
    if value.len() == limit {
        input.write_all(value.as_bytes())
    } else {
        writeln!(input, "{value}")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    challenge_id: String,
    method: Option<String>,
    username: Option<String>,
    password: Option<String>,
    private_key_password: Option<String>,
    response: Option<String>,
    cookie: Option<String>,
}
struct Relay {
    path: PathBuf,
    expires_at: u64,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<bool>>,
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl Relay {
    fn start(record: &Record, directory: &Path) -> io::Result<Self> {
        let namespace = File::open(Path::new("/run/netns").join(&record.namespace))?;
        let root = directory
            .parent()
            .ok_or_else(|| invalid("missing native runtime directory"))?;
        let path = root.join(format!("saml-{}.sock", random_id()?));
        let listener = UnixListener::bind(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        let socket = OwnedSocket {
            path: path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        chown(&path, Some(0), Some(fs::metadata(root)?.gid()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660))?;
        listener.set_nonblocking(true)?;
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = stopping.clone();
        let expires_at = now() + SAML_CALLBACK_SECONDS;
        let deadline = Instant::now() + Duration::from_secs(SAML_CALLBACK_SECONDS);
        let thread = thread::Builder::new().spawn(move || {
            let _socket = socket;
            // SAFETY: namespace is a live network namespace descriptor; only this dedicated thread changes namespace.
            if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                return false;
            }
            while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut browser, _)) => {
                        if Self::exchange(&mut browser, deadline).unwrap_or(false) {
                            return true;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
            false
        })?;
        Ok(Self {
            path,
            expires_at,
            stopping,
            thread: Some(thread),
        })
    }
    fn timeout_until(deadline: Instant) -> io::Result<Duration> {
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(1));
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SAML callback timed out",
            ));
        }
        Ok(timeout)
    }
    fn callback_id(text: &str) -> io::Result<&str> {
        let mut parts = text.lines().next().unwrap_or("").split_whitespace();
        let method = parts.next();
        let path = parts
            .next()
            .ok_or_else(|| invalid("SAML callback path missing"))?;
        let version = parts.next();
        if method != Some("GET")
            || version != Some("HTTP/1.1")
            || parts.next().is_some()
            || !path.starts_with("/?id=")
        {
            return Err(invalid("unsupported SAML callback request"));
        }
        let id = path
            .strip_prefix("/?id=")
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        if id.is_empty()
            || id.len() > 1024
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(invalid("invalid SAML callback identifier"));
        }
        Ok(id)
    }
    fn exchange(browser: &mut UnixStream, deadline: Instant) -> io::Result<bool> {
        browser.set_write_timeout(Some(Duration::from_secs(1)))?;
        let mut request = Vec::new();
        let request_deadline = deadline.min(Instant::now() + Duration::from_secs(2));
        while !request.ends_with(b"\r\n\r\n") {
            if request.len() >= 8192 {
                return Err(invalid("invalid SAML callback request"));
            }
            browser.set_read_timeout(Some(Self::timeout_until(request_deadline)?))?;
            let mut byte = [0];
            browser.read_exact(&mut byte)?;
            request.push(byte[0]);
        }
        let text =
            std::str::from_utf8(&request).map_err(|_| invalid("invalid SAML callback encoding"))?;
        let id = Self::callback_id(text)?;
        let mut native = TcpStream::connect_timeout(
            &"127.0.0.1:8020".parse().unwrap(),
            Self::timeout_until(deadline)?,
        )?;
        native.set_read_timeout(Some(Duration::from_secs(1)))?;
        native.set_write_timeout(Some(Self::timeout_until(deadline)?))?;
        native.write_all(
            format!("GET /?id={id} HTTP/1.1\r\nHost: 127.0.0.1:8020\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )?;
        let mut response = Vec::new();
        native.take(16385).read_to_end(&mut response)?;
        if response.len() > 16384 {
            return Err(invalid("native SAML callback response exceeds limit"));
        }
        // openfortivpn sends HTTP 200 for both accepted and rejected callbacks.
        let accepted = b"VPN will be established";
        let _ = browser.write_all(&response);
        Ok(response
            .windows(accepted.len())
            .any(|part| part == accepted))
    }
}

pub struct Session {
    profile: Profile,
    directory: PathBuf,
    executable: PathBuf,
    version: (u32, u32),
    stdin: Option<ChildStdin>,
    output: [Vec<u8>; 2],
    dns: Option<String>,
    ready: bool,
    relay: Option<Relay>,
}
impl Session {
    pub fn new(
        record: &Record,
        directory: &Path,
        executable: &Path,
        auth: &mut Authentication,
    ) -> io::Result<Self> {
        let profile = decoded_profile(&record.profile)?;
        let executable = super::executable(executable)?;
        let output = super::command(
            executable
                .to_str()
                .ok_or_else(|| invalid("invalid Forti executable path"))?,
            &["--version"],
        )?;
        let version = version(&output)?;
        let session = Self {
            profile,
            directory: directory.to_owned(),
            executable,
            version,
            stdin: None,
            output: [Vec::new(), Vec::new()],
            dns: None,
            ready: false,
            relay: None,
        };
        if !record.paused {
            auth.require(
                "password",
                "Forti credentials, certificate, cookie or SAML",
                None,
                String::new(),
            )?;
        }
        Ok(session)
    }
    pub fn action(&self, auth: &Authentication) -> Value {
        let mut value = auth.action();
        let mut methods = vec!["password", "cookie"];
        if self.profile.inline.contains_key("user-cert") {
            methods.push("certificate");
        }
        if self.version >= (1, 23) {
            methods.push("saml");
        }
        value["methods"] = json!(methods);
        if let Some(relay) = &self.relay {
            value["ssh_forward"] =
                json!({"local_host":"127.0.0.1","local_port":8020,"remote_socket":relay.path});
        }
        value
    }
    pub fn poll_callback(&mut self, auth: &mut Authentication) -> bool {
        let Some(relay) = self.relay.as_mut() else {
            return false;
        };
        if !relay.thread.as_ref().unwrap().is_finished() {
            return true;
        }
        let accepted = relay.thread.take().unwrap().join().unwrap_or(false);
        self.relay = None;
        if auth.state == "browser_required" {
            if accepted {
                auth.submitted();
                auth.expires_at = Some(now() + 300);
            } else {
                auth.expires_at = Some(now());
            }
        }
        false
    }
    pub fn automatic(
        &mut self,
        record: &Record,
        auth: &mut Authentication,
        child: &mut Option<Child>,
    ) -> io::Result<()> {
        if record.paused {
            return Ok(());
        }
        if auth.remembered
            && auth.credentials.username.is_some()
            && auth.credentials.password.is_some()
        {
            self.launch(record, auth, child, "password", None)?;
        } else if auth.remembered
            && auth.credentials.private_key_password.is_some()
            && self.profile.inline.contains_key("user-cert")
        {
            self.launch(record, auth, child, "certificate", None)?;
        }
        Ok(())
    }
    fn encrypted_key(&self) -> bool {
        self.profile
            .inline
            .get("user-key")
            .is_some_and(|key| key.contains("ENCRYPTED"))
    }
    pub fn submit(
        &mut self,
        record: &Record,
        auth: &mut Authentication,
        child: &mut Option<Child>,
        value: &Value,
        remember: bool,
    ) -> io::Result<()> {
        if auth.expire() {
            return Err(invalid(
                "authentication challenge expired; restart the applied connection",
            ));
        }
        let reply: Reply = serde_json::from_value(value.clone())
            .map_err(|_| invalid("invalid Forti authentication input"))?;
        let action = auth.action();
        if action["challenge_id"].as_str() != Some(&reply.challenge_id) {
            return Err(invalid(
                "authentication challenge changed or was already answered",
            ));
        }
        for field in [
            &reply.username,
            &reply.password,
            &reply.private_key_password,
            &reply.response,
            &reply.cookie,
        ]
        .into_iter()
        .flatten()
        {
            if field.len() > 4096 || field.chars().any(char::is_control) {
                return Err(invalid("invalid Forti authentication value"));
            }
        }
        if reply.username.as_ref().is_some_and(|s| s.len() > 64)
            || reply
                .password
                .as_ref()
                .is_some_and(|s| s.len() > PASSWORD_LIMIT)
            || reply
                .private_key_password
                .as_ref()
                .is_some_and(|s| s.len() > 31)
            || reply.response.as_ref().is_some_and(|s| s.len() > OTP_LIMIT)
        {
            return Err(invalid(
                "Forti authentication value exceeds its native limit",
            ));
        }
        if action["method"] == "text" {
            if reply.method.is_some()
                || reply.username.is_some()
                || reply.password.is_some()
                || reply.private_key_password.is_some()
                || reply.cookie.is_some()
                || remember
            {
                return Err(invalid("Forti challenge accepts only a transient response"));
            }
            let response = reply
                .response
                .filter(|v| !v.is_empty())
                .ok_or_else(|| invalid("Forti challenge response required"))?;
            let stdin = self
                .stdin
                .as_mut()
                .ok_or_else(|| invalid("native Forti challenge is no longer pending"))?;
            write_input(stdin, &response, OTP_LIMIT)?;
            auth.submitted();
            auth.expires_at = Some(now() + 300);
            return Ok(());
        }
        let method = reply.method.as_deref().unwrap_or("password");
        if reply.response.is_some()
            || !matches!(method, "password" | "certificate" | "cookie" | "saml")
        {
            return Err(invalid("unsupported Forti login method"));
        }
        if matches!(method, "cookie" | "saml")
            && (reply.username.is_some() || reply.password.is_some() || remember)
        {
            return Err(invalid("Forti SSO accepts only transient session input"));
        }
        if method != "cookie" && reply.cookie.is_some() {
            return Err(invalid("cookie requires Forti cookie login"));
        }
        if method == "saml" && self.version < (1, 23) {
            return Err(invalid(
                "native SAML requires openfortivpn 1.23 or newer; use cookie SSO or a separately installed supported client",
            ));
        }
        if method == "certificate"
            && (!self.profile.inline.contains_key("user-cert")
                || reply.username.is_some()
                || reply.password.is_some())
        {
            return Err(invalid(
                "certificate login requires a packaged certificate/key pair and no account credentials",
            ));
        }
        let mut staged = auth.clone();
        if method == "password" {
            if let Some(user) = reply.username {
                staged.credentials.username = Some(user);
            }
            if let Some(password) = reply.password {
                staged.credentials.password = Some(password);
            }
            if staged
                .credentials
                .username
                .as_ref()
                .is_none_or(|s| s.is_empty())
                || staged.credentials.password.is_none()
            {
                return Err(invalid("Forti username and password required"));
            }
        }
        if let Some(password) = reply.private_key_password {
            staged.credentials.private_key_password = Some(password);
        }
        if method == "certificate" {
            if remember && staged.credentials.private_key_password.is_none() {
                return Err(invalid(
                    "certificate login has no base password to remember",
                ));
            }
            staged.credentials.username = None;
            staged.credentials.password = None;
        }

        if self.encrypted_key() && staged.credentials.private_key_password.is_none() {
            return Err(invalid(
                "Forti encrypted client key requires private_key_password",
            ));
        }
        self.launch(record, &mut staged, child, method, reply.cookie.as_deref())?;
        if remember {
            staged.remembered = true;
        }
        *auth = staged;
        Ok(())
    }
    fn launch(
        &mut self,
        record: &Record,
        auth: &mut Authentication,
        child: &mut Option<Child>,
        method: &str,
        cookie: Option<&str>,
    ) -> io::Result<()> {
        if child.is_some() {
            return Err(invalid(
                "Forti client is already running; restart before changing login methods",
            ));
        }
        if method == "cookie" && cookie.is_none_or(|c| c.is_empty()) {
            return Err(invalid("Forti cookie required"));
        }
        if option(&self.profile, "sni").is_some() && self.version < (1, 22) {
            return Err(invalid("explicit SNI requires openfortivpn 1.22 or newer"));
        }
        let runtime = self.directory.join("forti-runtime");
        for directory in [
            &runtime,
            &self.directory.join("forti-ppp"),
            &self.directory.join("forti-home"),
            &runtime.join("lock"),
        ] {
            secure_directory(directory, 0o700, 0o077)?;
        }
        write_private(
            &self.directory.join("forti-ppp/options"),
            "noauth\nnoipv6\nnodefaultroute\nnoproxyarp\nnolog\n",
        )?;
        let host = option(&self.profile, "host").unwrap();
        let hosts = record
            .endpoints
            .iter()
            .map(|e| format!("{} {host}\n", e.address))
            .collect::<String>();
        write_private(
            &self.directory.join("forti-hosts"),
            &format!("127.0.0.1 localhost\n{hosts}"),
        )?;
        let mut config = String::new();
        for item in &self.profile.options {
            if item[0] == "trusted-cert" {
                config += &format!("trusted-cert = {}\n", item[1].to_ascii_lowercase());
            } else if !matches!(
                item[0].as_str(),
                "set-routes" | "set-dns" | "pppd-use-peerdns" | "use-resolvconf" | "persistent"
            ) {
                config += &format!("{} = {}\n", item[0], item[1]);
            }
        }
        for (kind, contents) in &self.profile.inline {
            write_private(&runtime.join(format!("{kind}.pem")), contents)?;
            config += &format!("{kind} = /run/{kind}.pem\n");
        }
        config += "set-routes = 0\nset-dns = 0\npppd-use-peerdns = 0\nuse-resolvconf = 0\npersistent = 0\n";
        if matches!(method, "password" | "certificate") {
            let user = if method == "password" {
                auth.credentials.username.as_deref().unwrap()
            } else {
                ""
            };
            if user.trim() != user {
                return Err(invalid(
                    "Forti native config cannot preserve username whitespace",
                ));
            }
            config += &format!("username = {user}\n");
            if method == "certificate" {
                config += "password =\n";
            }
        }
        if let Some(password) = &auth.credentials.private_key_password {
            if password.trim() != password {
                return Err(invalid(
                    "Forti native config cannot preserve key password whitespace",
                ));
            }
            config += &format!("pem-passphrase = {password}\n");
        }
        // The native client reads the config once. Its PEM passphrase has no named file.
        // SAFETY: the name is a static C string. A successful call returns a new owned fd.
        let fd = unsafe { libc::memfd_create(c"wgates-forti-config".as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful memfd_create transferred ownership of fd to this File.
        let mut config_file = unsafe { File::from_raw_fd(fd) };
        config_file.set_permissions(fs::Permissions::from_mode(0o600))?;
        config_file.write_all(config.as_bytes())?;
        config_file.rewind()?;
        let config_path = format!("/proc/self/fd/{fd}");
        let relay = (method == "saml")
            .then(|| Relay::start(record, &self.directory))
            .transpose()?;
        let mut args = vec!["--config", &config_path, "--pppd-ifname=wgates-tun"];
        if method == "cookie" {
            args.push("--cookie-on-stdin");
        }
        if method == "saml" {
            args.push("--saml-login=8020");
        }
        if let Some(relay) = &relay {
            let mut url = url::Url::parse(&format!(
                "https://{host}:{}/remote/saml/start",
                option(&self.profile, "port").unwrap_or("443")
            ))
            .map_err(|_| invalid("invalid Forti SAML endpoint"))?;
            url.query_pairs_mut().append_pair("redirect", "1");
            if let Some(realm) = option(&self.profile, "realm") {
                url.query_pairs_mut().append_pair("realm", realm);
            }
            auth.require(
                "web",
                "Open the URL after establishing the reported SSH forward",
                Some(url.to_string()),
                String::new(),
            )?;
            auth.expires_at = Some(relay.expires_at);
        }
        let process = namespace_child(
            record,
            &self.executable,
            &args,
            Stdio::piped(),
            None,
            Some((&self.directory, &config_file)),
        )?;
        let mut process = Some(process);
        let mut stdin = process.as_mut().unwrap().stdin.take();
        if let Some(cookie) = cookie
            && let Err(error) = stdin.take().unwrap().write_all(cookie.as_bytes())
        {
            super::stop(&mut process);
            return Err(error);
        }
        if relay.is_none() {
            auth.submitted();
            auth.expires_at = Some(now() + 300);
        }
        self.relay = relay;
        self.stdin = stdin;
        *child = process;
        self.output = [Vec::new(), Vec::new()];
        self.ready = false;
        self.dns = None;
        Ok(())
    }
    pub fn poll(
        &mut self,
        record: &Record,
        auth: &mut Authentication,
        child: &mut Child,
    ) -> io::Result<Option<String>> {
        for index in 0..2 {
            let reader: &mut dyn Read = if index == 0 {
                child.stdout.as_mut().unwrap()
            } else {
                child.stderr.as_mut().unwrap()
            };
            for _ in 0..16 {
                let mut chunk = [0; 4096];
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        self.output[index].extend_from_slice(&chunk[..n]);
                        if self.output[index].len() > 65536 {
                            return Err(invalid("native Forti output exceeds limit"));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            let password_prompt = b"VPN account password: ";
            if let Some(position) = self.output[index]
                .windows(password_prompt.len())
                .position(|w| w == password_prompt)
            {
                self.output[index].drain(..position + password_prompt.len());
                let password = auth
                    .credentials
                    .password
                    .as_deref()
                    .ok_or_else(|| invalid("Forti password unavailable"))?;
                let stdin = self
                    .stdin
                    .as_mut()
                    .ok_or_else(|| invalid("Forti password input unavailable"))?;
                write_input(stdin, password, PASSWORD_LIMIT)?;
            }
            let prompt = b"Two-factor authentication token: ";
            if let Some(position) = self.output[index]
                .windows(prompt.len())
                .position(|w| w == prompt)
            {
                self.output[index].drain(..position + prompt.len());
                auth.require("text", "Forti one-time response", None, String::new())?;
            }
            while !self.output[index].is_empty() {
                if index == 0
                    && matches!(auth.state.as_str(), "authenticating" | "browser_required")
                {
                    let text = &self.output[index];
                    if text.starts_with(b"Please")
                        || option(&self.profile, "otp-prompt")
                            .is_some_and(|prefix| text.starts_with(prefix.as_bytes()))
                    {
                        if text.len() > 79 {
                            return Err(invalid("unsupported native Forti prompt"));
                        }
                        let text = std::str::from_utf8(text)
                            .map_err(|_| invalid("invalid native Forti prompt encoding"))?;
                        let prompt = text.split_whitespace().collect::<Vec<_>>().join(" ");
                        auth.require("text", &prompt, None, String::new())?;
                        self.output[index].clear();
                        break;
                    }
                }
                let Some(end) = self.output[index].iter().position(|b| *b == b'\n') else {
                    break;
                };
                let line = String::from_utf8(self.output[index].drain(..=end).collect())
                    .map_err(|_| invalid("invalid native Forti output encoding"))?;
                if line.contains("Could not authenticate")
                    || line.contains("Authentication failed")
                    || line.contains("authentication failed")
                {
                    auth.fail("authentication_rejected");
                } else if line.contains("Gateway certificate validation failed")
                    || line.contains("certificate verify failed")
                {
                    return Err(invalid("server_certificate_verification_failed"));
                } else if line.contains("Connected to gateway") {
                    auth.reason = "forti_gateway_connected".into();
                } else if line.contains("Authenticated") {
                    auth.reason = "forti_authentication_accepted".into();
                } else if line.contains("Remote gateway has allocated") {
                    auth.reason = "forti_tunnel_allocated".into();
                } else if line.contains("Negotiation complete") {
                    auth.reason = "forti_ppp_negotiated".into();
                } else if line.contains("Got addresses:") {
                    if let Some(text) = line
                        .split_once("ns [")
                        .and_then(|(_, s)| s.split_once(']').map(|p| p.0))
                    {
                        self.dns = text
                            .split(',')
                            .filter_map(|s| s.trim().parse::<Ipv4Addr>().ok())
                            .find(|ip| {
                                !ip.is_unspecified()
                                    && !ip.is_multicast()
                                    && !ip.is_loopback()
                                    && !ip.is_broadcast()
                            })
                            .map(|ip| format!("udp://{ip}:53"));
                    }
                } else if line.contains("Tunnel is up and running") {
                    super::ns(
                        record,
                        &[
                            "-4",
                            "route",
                            "replace",
                            "default",
                            "dev",
                            "wgates-tun",
                            "metric",
                            "50",
                        ],
                    )?;
                    self.ready = true;
                    auth.authenticated("native_tunnel_ready");
                    self.relay = None;
                }
            }
        }
        Ok(if self.ready { self.dns.clone() } else { None })
    }
    pub fn stopped(&mut self) {
        self.stdin = None;
        self.relay = None;
        self.dns = None;
        self.ready = false;
    }
}
fn write_private(path: &Path, text: &str) -> io::Result<()> {
    if path.exists() {
        crate::store::private_read(path, 2 * 1024 * 1024)?;
        fs::remove_file(path)?;
    }
    private_text(path, text)
}
pub fn version(output: &str) -> io::Result<(u32, u32)> {
    let fields: Vec<_> = output.trim().split('.').collect();
    let (major, minor) = (
        fields.first().and_then(|v| v.parse().ok()),
        fields.get(1).and_then(|v| v.parse().ok()),
    );
    match (major, minor) {
        (Some(1), Some(minor @ 21..=24)) => Ok((1, minor)),
        _ => Err(invalid(
            "native Forti requires a supported openfortivpn 1.21 through 1.24 client",
        )),
    }
}

pub fn mounts(directory: &Path) -> io::Result<Vec<(std::ffi::CString, std::ffi::CString)>> {
    use std::ffi::{CStr, CString};
    // SAFETY: getpwuid returns a libc-owned record; copy its home path immediately.
    let home = unsafe {
        let account = libc::getpwuid(0);
        if account.is_null() || (*account).pw_dir.is_null() {
            return Err(invalid("root home unavailable for PPP isolation"));
        }
        CStr::from_ptr((*account).pw_dir).to_bytes().to_vec()
    };
    let home = {
        use std::os::unix::ffi::OsStringExt;
        PathBuf::from(std::ffi::OsString::from_vec(home))
    };
    if !home.is_absolute() || home == Path::new("/") {
        return Err(invalid("unsupported root home for PPP isolation"));
    }
    let sources = [
        (directory.join("forti-ppp"), PathBuf::from("/etc/ppp")),
        (directory.join("forti-home"), home),
        (directory.join("forti-hosts"), PathBuf::from("/etc/hosts")),
        (
            directory.join("forti-runtime/lock"),
            Path::new("/var/lock").canonicalize()?,
        ),
        (directory.join("forti-runtime"), PathBuf::from("/run")),
    ];
    sources
        .into_iter()
        .map(|(source, target)| {
            let source = CString::new(source.as_os_str().as_encoded_bytes())
                .map_err(|_| invalid("invalid private Forti mount source"))?;
            let target = CString::new(target.as_os_str().as_encoded_bytes())
                .map_err(|_| invalid("invalid private Forti mount target"))?;
            Ok((source, target))
        })
        .collect()
}

pub fn cleanup(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if !matches!(
        name,
        "forti-hosts" | "forti-ppp" | "forti-home" | "forti-runtime"
    ) {
        return Err(invalid("unknown Forti runtime resource retained"));
    }
    fn inspect(path: &Path, relative: &str, entries: &mut Vec<PathBuf>) -> io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.file_type().is_symlink()
            || !(metadata.is_dir() || metadata.is_file() && metadata.nlink() == 1)
        {
            return Err(invalid(
                "Forti runtime ownership changed; retain resources for inspection",
            ));
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name
                    .to_str()
                    .ok_or_else(|| invalid("unknown Forti runtime resource retained"))?;
                let child = format!("{relative}/{name}");
                let allowed = match relative {
                    "forti-ppp" => name == "options" || name == "resolv.conf",
                    "forti-home" => name == ".rnd",
                    "forti-runtime" => {
                        matches!(
                            name,
                            "lock"
                                | "ppp"
                                | "forti.conf"
                                | "ca-file.pem"
                                | "user-cert.pem"
                                | "user-key.pem"
                                | "ppp-wgates-tun.pid"
                                | "pppd2.tdb"
                                | "utmp"
                        ) || name
                            .strip_prefix("ppp")
                            .and_then(|s| s.strip_suffix(".pid"))
                            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                    }
                    "forti-runtime/lock" => name.starts_with("LCK.."),
                    "forti-runtime/ppp" => name.ends_with(".pid") && !name.contains('/'),
                    _ => false,
                };
                if !allowed {
                    return Err(invalid("unknown Forti runtime file retained"));
                }
                inspect(&entry.path(), &child, entries)?;
            }
        }
        entries.push(path.to_owned());
        Ok(())
    }
    let mut entries = Vec::new();
    inspect(path, name, &mut entries)?;
    for entry in entries {
        if fs::symlink_metadata(&entry)?.is_dir() {
            fs::remove_dir(entry)?;
        } else {
            fs::remove_file(entry)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saml_callback_keeps_the_native_identifier_with_extra_parameters() {
        let request = "GET /?id=fixture-id&realm=office HTTP/1.1\r\n\r\n";
        assert_eq!(Relay::callback_id(request).unwrap(), "fixture-id");
    }

    #[test]
    fn saml_completion_preserves_an_existing_otp_challenge() {
        let mut session = Session {
            profile: Profile {
                options: Vec::new(),
                inline: Default::default(),
            },
            directory: PathBuf::new(),
            executable: PathBuf::new(),
            version: (1, 24),
            stdin: None,
            output: Default::default(),
            dns: None,
            ready: false,
            relay: Some(Relay {
                path: PathBuf::new(),
                expires_at: now() + SAML_CALLBACK_SECONDS,
                stopping: Arc::new(AtomicBool::new(false)),
                thread: Some(thread::spawn(|| true)),
            }),
        };
        let mut auth = Authentication::new(Default::default(), false).unwrap();
        auth.require("text", "One-time code", None, String::new())
            .unwrap();
        let challenge = auth.action();
        let deadline = Instant::now() + Duration::from_secs(2);
        while session.relay.is_some() {
            assert!(Instant::now() < deadline);
            session.poll_callback(&mut auth);
            thread::yield_now();
        }
        assert_eq!(auth.action(), challenge);
    }

    #[test]
    fn expired_saml_callback_returns_before_reading_the_request() {
        let (mut relay, _browser) = UnixStream::pair().unwrap();
        let error = Relay::exchange(&mut relay, Instant::now()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
