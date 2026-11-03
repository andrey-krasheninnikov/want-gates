use crate::forti::{decoded_profile, option};
use crate::native_runtime::{Record, namespace_child, private_text};
use crate::openvpn::Profile;
use crate::openvpn_auth::{Authentication, now};
use crate::{invalid, secure_directory};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

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
    port: u16,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
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
    fn start(record: &Record) -> io::Result<Self> {
        let namespace = File::open(Path::new("/run/netns").join(&record.namespace))?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = stopping.clone();
        let thread = thread::spawn(move || {
            // SAFETY: namespace is a live network namespace descriptor; only this dedicated thread changes namespace.
            if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                return;
            }
            let deadline = Instant::now() + Duration::from_secs(50);
            while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut browser, _)) => {
                        if Self::exchange(&mut browser).is_ok() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            port,
            stopping,
            thread: Some(thread),
        })
    }
    fn exchange(browser: &mut TcpStream) -> io::Result<()> {
        browser.set_read_timeout(Some(Duration::from_secs(1)))?;
        browser.set_write_timeout(Some(Duration::from_secs(1)))?;
        let mut request = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !request.ends_with(b"\r\n\r\n") {
            if request.len() >= 8192 || Instant::now() >= deadline {
                return Err(invalid("invalid SAML callback request"));
            }
            let mut byte = [0];
            browser.read_exact(&mut byte)?;
            request.push(byte[0]);
        }
        let text =
            std::str::from_utf8(&request).map_err(|_| invalid("invalid SAML callback encoding"))?;
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
        let url = url::Url::parse(&format!("http://127.0.0.1:8020{path}"))
            .map_err(|_| invalid("invalid SAML callback URL"))?;
        let pairs: Vec<_> = url.query_pairs().collect();
        if pairs.len() != 1
            || pairs[0].0 != "id"
            || pairs[0].1.is_empty()
            || pairs[0].1.len() > 1024
            || pairs[0].1.chars().any(char::is_control)
        {
            return Err(invalid("invalid SAML callback identifier"));
        }
        let mut native =
            TcpStream::connect_timeout(&"127.0.0.1:8020".parse().unwrap(), Duration::from_secs(1))?;
        native.set_read_timeout(Some(Duration::from_secs(1)))?;
        native.set_write_timeout(Some(Duration::from_secs(1)))?;
        write!(
            native,
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:8020\r\nConnection: close\r\n\r\n"
        )?;
        let mut response = Vec::new();
        native.take(16385).read_to_end(&mut response)?;
        if response.len() > 16384 {
            return Err(invalid("native SAML callback response exceeds limit"));
        }
        browser.write_all(&response)?;
        Ok(())
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
            executable: executable.to_owned(),
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
            value["ssh_forward"] = json!({"local_host":"127.0.0.1","local_port":8020,"remote_host":"127.0.0.1","remote_port":relay.port});
        }
        value
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
            || reply.password.as_ref().is_some_and(|s| s.len() > 256)
            || reply
                .private_key_password
                .as_ref()
                .is_some_and(|s| s.len() > 31)
            || reply.response.as_ref().is_some_and(|s| s.len() > 64)
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
            writeln!(stdin, "{response}")?;
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
        if method == "password" {
            if let Some(user) = reply.username {
                auth.credentials.username = Some(user);
            }
            if let Some(password) = reply.password {
                auth.credentials.password = Some(password);
            }
            if auth
                .credentials
                .username
                .as_ref()
                .is_none_or(|s| s.is_empty())
                || auth.credentials.password.is_none()
            {
                return Err(invalid("Forti username and password required"));
            }
        }
        if let Some(password) = reply.private_key_password {
            auth.credentials.private_key_password = Some(password);
        }
        if method == "certificate" {
            if remember && auth.credentials.private_key_password.is_none() {
                return Err(invalid(
                    "certificate login has no base password to remember",
                ));
            }
            auth.credentials.username = None;
            auth.credentials.password = None;
        }

        if self.encrypted_key() && auth.credentials.private_key_password.is_none() {
            return Err(invalid(
                "Forti encrypted client key requires private_key_password",
            ));
        }
        self.launch(record, auth, child, method, reply.cookie.as_deref())?;
        if remember {
            auth.remembered = true;
        }
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
            if !matches!(
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
        write_private(&runtime.join("forti.conf"), &config)?;
        let mut args = vec!["--config", "/run/forti.conf", "--pppd-ifname=wgates-tun"];
        if method == "cookie" {
            args.push("--cookie-on-stdin");
        }
        if method == "saml" {
            args.push("--saml-login=8020");
        }
        let mut process = namespace_child(
            record,
            &self.executable,
            &args,
            Stdio::piped(),
            None,
            Some(&self.directory),
        )?;
        self.stdin = process.stdin.take();
        *child = Some(process);
        self.output = [Vec::new(), Vec::new()];
        self.ready = false;
        self.dns = None;
        auth.submitted();
        auth.expires_at = Some(now() + 300);
        if let Some(cookie) = cookie {
            let result = self.stdin.as_mut().unwrap().write_all(cookie.as_bytes());
            self.stdin = None;
            result?;
        }
        if method == "saml" {
            self.relay = Some(Relay::start(record)?);
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
            auth.expires_at = Some(now() + 50);
        }
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
                writeln!(stdin, "{password}")?;
            }
            let prompt = b"Two-factor authentication token: ";
            if let Some(position) = self.output[index]
                .windows(prompt.len())
                .position(|w| w == prompt)
            {
                self.output[index].drain(..position + prompt.len());
                auth.require("text", "Forti one-time response", None, String::new())?;
            }
            while let Some(end) = self.output[index].iter().position(|b| *b == b'\n') {
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
                    auth.state = "authenticated".into();
                    auth.reason = "native_tunnel_ready".into();
                    auth.expires_at = None;
                    self.relay = None;
                }
            }
            if index == 0 && auth.state == "authenticating" && !self.output[index].is_empty() {
                let text = std::str::from_utf8(&self.output[index])
                    .map_err(|_| invalid("invalid native Forti prompt encoding"))?;
                if text.starts_with("Please")
                    || option(&self.profile, "otp-prompt")
                        .is_some_and(|prefix| text.starts_with(prefix))
                {
                    if text.len() > 79 {
                        return Err(invalid("unsupported native Forti prompt"));
                    }
                    auth.require("text", text, None, String::new())?;
                    self.output[index].clear();
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
