use crate::native::{Observation, Prepared};
use crate::openvpn_auth::{Authentication, Credentials};
use crate::store::{private_read, private_write, random_id};
use crate::{API_VERSION, invalid, read_message, secure_directory, write_message};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    address: IpAddr,
    port: u16,
    protocol: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    prepared: Prepared,
    profile: Value,
    namespace: String,
    interface: String,
    peer: String,
    host: Ipv4Addr,
    host6: Ipv6Addr,
    peer6: Ipv6Addr,
    endpoints: Vec<Endpoint>,
    namespace_identity: Option<(u64, u64)>,
    #[serde(default)]
    namespace_file: Option<(u64, u64)>,
    firewall_digest: Option<String>,
    paused: bool,
}
impl Record {
    fn validate(&self) -> io::Result<()> {
        let p = &self.prepared;
        let address = match p.address {
            IpAddr::V4(ip) => ip,
            _ => return Err(invalid("invalid native bridge family")),
        };
        let octets = self.host.octets();
        let index = (u16::from(octets[2]) << 6) | (u16::from(octets[3]) >> 2);
        let endpoint_valid = |e: &Endpoint| {
            e.port != 0
                && matches!(e.protocol.as_str(), "tcp" | "udp")
                && !e.address.is_loopback()
                && !e.address.is_unspecified()
                && !e.address.is_multicast()
                && e.address != IpAddr::V4(Ipv4Addr::BROADCAST)
                && !matches!(e.address, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() || ip.is_unicast_link_local())
        };
        if !valid_id(&p.id)
            || !valid_generation(&p.generation)
            || p.profile_digest != crate::routing::digest(&self.profile)?
            || self.namespace != format!("wgates-{}", p.generation)
            || self.interface != format!("wgn{}", &p.generation[..10])
            || self.peer != format!("wgp{}", &p.generation[..10])
            || octets[..2] != [169, 254]
            || octets[3] % 4 != 1
            || index == 0
            || index >= 16384
            || u32::from(address) != u32::from(self.host) + 1
            || self.host6 != Ipv6Addr::new(0xfd72, 0x7767, 0x6174, index, 0, 0, 0, 1)
            || self.peer6 != Ipv6Addr::new(0xfd72, 0x7767, 0x6174, index, 0, 0, 0, 2)
            || p.data_port != 22100
            || p.probe_port != 22101
            || [&p.password, &p.probe_password]
                .iter()
                .any(|s| !valid_generation(s))
            || self.endpoints.is_empty()
            || self.endpoints.len() > 32
            || !self.endpoints.iter().all(endpoint_valid)
        {
            return Err(invalid(
                "retained native state is inconsistent; retain resources for inspection",
            ));
        }
        profile(&self.profile)?;
        Ok(())
    }
}

struct Instance {
    record: Record,
    auth: Authentication,
    openvpn: Option<Child>,
    proxy: Option<Child>,
    listener: Option<UnixListener>,
    management: Option<UnixStream>,
    buffer: Vec<u8>,
    environment: Option<BTreeMap<String, String>>,
    dns: Option<String>,
    admitted_session: Option<String>,
    proxy_gate: Option<bool>,
}
struct Runtime {
    root: PathBuf,
    directory: PathBuf,
    uid: u32,
    gid: u32,
    xray: PathBuf,
    instances: BTreeMap<String, Instance>,
}

fn valid_generation(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn valid_id(s: &str) -> bool {
    s.strip_prefix('c')
        .is_some_and(|s| !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()))
}
fn controlled_path(path: &Path) -> io::Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("native path parent required"))?
        .canonicalize()?;
    for directory in parent.ancestors() {
        let metadata = fs::metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(invalid(
                "native parent directories must be controlled by root and not writable by other users",
            ));
        }
    }
    Ok(parent.join(
        path.file_name()
            .ok_or_else(|| invalid("native path name required"))?,
    ))
}

fn executable(path: &Path) -> io::Result<PathBuf> {
    let path = path.canonicalize()?;
    let m = fs::metadata(&path)?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.mode() & 0o111 == 0 {
        return Err(invalid(
            "native executable must be root-owned and not writable by other users",
        ));
    }
    for parent in path.ancestors().skip(1) {
        let m = fs::metadata(parent)?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(invalid(
                "native executable directory must be controlled by root",
            ));
        }
    }
    Ok(path)
}
fn command(program: &str, args: &[&str]) -> io::Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child.stdout.take().unwrap();
    // SAFETY: stdout is this child's live pipe; only O_NONBLOCK is added.
    if unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::last_os_error());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = (|| {
        let mut output = Vec::new();
        let mut finished: Option<std::process::ExitStatus> = None;
        loop {
            let mut chunk = [0; 4096];
            loop {
                match stdout.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        if output.len() + n > 1024 * 1024 {
                            return Err(invalid("native network output exceeds its limit"));
                        }
                        output.extend_from_slice(&chunk[..n]);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            if let Some(status) = finished {
                if !status.success() {
                    return Err(invalid(&format!(
                        "native {} operation failed; inspect prerequisites and owned resources",
                        program.rsplit('/').next().unwrap_or("executable")
                    )));
                }
                return String::from_utf8(output)
                    .map_err(|_| invalid("invalid native network output"));
            }
            if let Some(status) = child.try_wait()? {
                finished = Some(status);
                continue;
            }
            if Instant::now() >= deadline {
                return Err(invalid("native network operation timed out"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
fn nft(namespace: Option<&str>, script: &str) -> io::Result<()> {
    let mut cmd = if let Some(namespace) = namespace {
        let mut c = Command::new("/usr/sbin/ip");
        c.args(["netns", "exec", namespace, "/usr/sbin/nft"]);
        c
    } else {
        Command::new("/usr/sbin/nft")
    };
    let mut child = cmd
        .args(["-f", "-"])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{script}\n").as_bytes())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(invalid("native firewall operation failed"))
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(invalid("native firewall operation timed out"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn nft_digest(table: &str) -> io::Result<String> {
    let mut value: Value = serde_json::from_str(&command(
        "/usr/sbin/nft",
        &["-j", "list", "table", "inet", table],
    )?)
    .map_err(|_| invalid("invalid native firewall readback"))?;
    fn clean(v: &mut Value) {
        match v {
            Value::Object(o) => {
                o.remove("handle");
                for v in o.values_mut() {
                    clean(v);
                }
            }
            Value::Array(a) => {
                a.retain(|v| v.get("metainfo").is_none());
                for v in a {
                    clean(v);
                }
            }
            _ => {}
        }
    }
    clean(&mut value);
    crate::routing::digest(&value)
}
fn ns(record: &Record, args: &[&str]) -> io::Result<String> {
    let mut all = vec!["-n", record.namespace.as_str()];
    all.extend_from_slice(args);
    command("/usr/sbin/ip", &all)
}
fn stop(child: &mut Option<Child>) {
    if let Some(mut child) = child.take() {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        // SAFETY: the PID belongs to this owned child; it is reaped before return.
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
fn namespace_child(
    record: &Record,
    program: &Path,
    args: &[&str],
    stdin: Stdio,
    uid: Option<(u32, u32)>,
) -> io::Result<Child> {
    let namespace = File::open(Path::new("/run/netns").join(&record.namespace))?;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: getpid has no arguments and cannot fail.
    let parent = unsafe { libc::getpid() };
    // SAFETY: after fork this closure uses only async-signal-safe Linux syscalls, then execs the fixed executable.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            if libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if let Some((uid, gid)) = uid {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
            } else {
                for capability in 0..=40 {
                    if capability != 12
                        && libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
            // Changing UID clears PDEATHSIG, so arm it after credentials and check the parent again.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 || libc::getppid() != parent
            {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    for fd in [
        child.stdout.as_ref().map(AsRawFd::as_raw_fd),
        child.stderr.as_ref().map(AsRawFd::as_raw_fd),
    ]
    .into_iter()
    .flatten()
    {
        // SAFETY: fd is this child's live pipe; only O_NONBLOCK is added to its current flags.
        if unsafe {
            libc::fcntl(
                fd,
                libc::F_SETFL,
                libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(child)
}
fn read_diagnostic(reader: &mut impl Read) -> io::Result<Option<&'static str>> {
    let mut buffer = [0; 4096];
    let mut reason = None;
    for _ in 0..16 {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let text = String::from_utf8_lossy(&buffer[..count]);
                for (marker, code) in [
                    ("VERIFY ERROR:", "server_certificate_verification_failed"),
                    ("TLS Error:", "tls_handshake_failed"),
                    ("Options error:", "profile_runtime_rejected"),
                    ("Cannot open TUN", "tun_unavailable"),
                    ("Failed to start:", "native_proxy_failed"),
                ] {
                    if text.contains(marker) {
                        reason = Some(code);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(reason)
}
fn child_diagnostic(child: &mut Option<Child>) -> io::Result<Option<&'static str>> {
    let mut reason = None;
    if let Some(child) = child {
        if let Some(stdout) = &mut child.stdout {
            reason = read_diagnostic(stdout)?;
        }
        if let Some(stderr) = &mut child.stderr {
            reason = read_diagnostic(stderr)?.or(reason);
        }
    }
    Ok(reason)
}
fn private_text(path: &Path, text: &str) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()
}
fn profile(value: &Value) -> io::Result<crate::openvpn::Profile> {
    let mut value = crate::openvpn::parse(&value.to_string())?;
    value.as_object_mut().unwrap().remove("protocol");
    serde_json::from_value(value).map_err(|_| invalid("invalid native profile"))
}
fn endpoints(profile: &crate::openvpn::Profile) -> io::Result<Vec<Endpoint>> {
    let protocol = profile
        .options
        .iter()
        .find(|o| o[0] == "proto")
        .map(|o| o[1].as_str())
        .unwrap_or("udp");
    let port = profile
        .options
        .iter()
        .find(|o| o[0] == "port")
        .map(|o| o[1].parse::<u16>().unwrap())
        .unwrap_or(1194);
    let mut result = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    for remote in profile.options.iter().filter(|o| o[0] == "remote") {
        if Instant::now() >= deadline {
            return Err(invalid(
                "VPN endpoint bootstrap resolution exceeded its total deadline",
            ));
        }
        let protocol = remote.get(3).map(String::as_str).unwrap_or(protocol);
        let port = remote
            .get(2)
            .map(|p| p.parse::<u16>().unwrap())
            .unwrap_or(port);
        let addresses = if let Ok(ip) = remote[1].parse::<IpAddr>() {
            vec![ip]
        } else {
            command("/usr/bin/getent", &["ahosts", &remote[1]])
                .map_err(|_| invalid("VPN endpoint bootstrap resolution failed or timed out"))?
                .lines()
                .filter_map(|line| line.split_whitespace().next()?.parse::<IpAddr>().ok())
                .take(32)
                .collect()
        };
        for ip in addresses {
            if ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_loopback()
                || matches!(ip,IpAddr::V6(v) if v.to_ipv4_mapped().is_some() || v.is_unicast_link_local())
                || ip == IpAddr::V4(Ipv4Addr::BROADCAST)
            {
                continue;
            }
            if (protocol.contains('4') && !ip.is_ipv4())
                || (protocol.contains('6') && !ip.is_ipv6())
            {
                continue;
            }
            let transport = if protocol.starts_with("tcp") {
                "tcp"
            } else {
                "udp"
            };
            if !result
                .iter()
                .any(|e: &Endpoint| e.address == ip && e.port == port && e.protocol == transport)
            {
                result.push(Endpoint {
                    address: ip,
                    port,
                    protocol: transport.into(),
                });
            }
        }
    }
    if result.is_empty() || result.len() > 32 {
        return Err(invalid(
            "OpenVPN endpoints have no supported unicast addresses or exceed the endpoint limit",
        ));
    }
    Ok(result)
}
impl Runtime {
    fn record_path(&self, generation: &str) -> PathBuf {
        self.root.join(format!("{generation}.json"))
    }
    fn save(&self, record: &Record) -> io::Result<()> {
        private_write(&self.record_path(&record.prepared.generation), record)
    }
    fn auth_path(&self, record: &Record) -> PathBuf {
        self.root.join(format!(
            "{}-{}.auth",
            record.prepared.id, record.prepared.profile_digest
        ))
    }
    fn preflight(&self) -> io::Result<Value> {
        for path in [
            "/usr/sbin/ip",
            "/usr/sbin/nft",
            "/usr/sbin/openvpn",
            "/usr/bin/getent",
            "/usr/sbin/sysctl",
            "/usr/bin/true",
        ] {
            executable(Path::new(path))?;
        }
        let version = command("/usr/sbin/openvpn", &["--version"])?;
        if !version.starts_with("OpenVPN 2.6.") {
            return Err(invalid("native runtime requires supported OpenVPN 2.6.x"));
        }
        if !command(
            self.xray
                .to_str()
                .ok_or_else(|| invalid("invalid Xray executable path"))?,
            &["version"],
        )?
        .contains("26.9.9")
        {
            return Err(invalid("native runtime requires Xray 26.9.9"));
        }
        if !Path::new("/dev/net/tun").exists() {
            return Err(invalid(
                "TUN unavailable; provide /dev/net/tun to the native runtime",
            ));
        }
        if fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?.trim() != "1" {
            return Err(invalid(
                "IPv4 forwarding disabled; enable net.ipv4.ip_forward manually after checking host routing",
            ));
        }
        Ok(
            json!({"openvpn":version.lines().next(),"xray":"26.9.9","ipv4_forwarding":true,"ipv6_forwarding":fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding").ok().is_some_and(|s|s.trim()=="1")}),
        )
    }
    fn prepare(&mut self, id: &str, generation: &str, value: &Value) -> io::Result<Value> {
        if !valid_id(id) || !valid_generation(generation) {
            return Err(invalid("invalid native connection or generation identity"));
        }
        let profile = profile(value)?;
        let digest = crate::routing::digest(value)?;
        if let Some(instance) = self.instances.get(generation) {
            if instance.record.prepared.id != id
                || instance.record.prepared.profile_digest != digest
            {
                return Err(invalid(
                    "native generation already belongs to different input",
                ));
            }
            return Ok(json!(instance.record.prepared));
        }
        self.preflight()?;
        let endpoints = endpoints(&profile)?;
        if endpoints.iter().any(|e| e.address.is_ipv6())
            && fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")?.trim() != "1"
        {
            return Err(invalid(
                "IPv6 endpoint requires net.ipv6.conf.all.forwarding; configure it manually after checking host management access",
            ));
        }
        let used = command("/usr/sbin/ip", &["-j", "address", "show"])?;
        let routes: Value = serde_json::from_str(&command(
            "/usr/sbin/ip",
            &["-j", "route", "show", "table", "all"],
        )?)?;
        let seed = u16::from_str_radix(&generation[..4], 16).unwrap() as u32;
        let index = (1..16383u32)
            .map(|offset| (seed + offset) % 16383 + 1)
            .find(|index| {
                let host =
                    Ipv4Addr::new(169, 254, (index >> 6) as u8, ((index & 63) * 4 + 1) as u8);
                let peer = Ipv4Addr::from(u32::from(host) + 1);
                let network = crate::policy::Network::parse(&format!("{host}/30")).unwrap();
                !used.contains(&host.to_string())
                    && !used.contains(&peer.to_string())
                    && !routes
                        .as_array()
                        .unwrap_or(&Vec::new())
                        .iter()
                        .filter_map(|r| r["dst"].as_str())
                        .filter_map(|n| crate::policy::Network::parse(n).ok())
                        .any(|n| n.contains(IpAddr::V4(host)) || network.contains(n.address))
            })
            .ok_or_else(|| {
                invalid("no collision-free native bridge address; inspect link-local host routes")
            })?;
        let host = Ipv4Addr::new(169, 254, (index >> 6) as u8, ((index & 63) * 4 + 1) as u8);
        let peer = Ipv4Addr::from(u32::from(host) + 1);
        let host6 = Ipv6Addr::new(0xfd72, 0x7767, 0x6174, index as u16, 0, 0, 0, 1);
        let peer6 = Ipv6Addr::new(0xfd72, 0x7767, 0x6174, index as u16, 0, 0, 0, 2);
        let prepared = Prepared {
            id: id.into(),
            generation: generation.into(),
            profile_digest: digest,
            address: IpAddr::V4(peer),
            data_port: 22100,
            probe_port: 22101,
            password: random_id()?,
            probe_password: random_id()?,
        };
        let mut record = Record {
            prepared,
            profile: value.clone(),
            namespace: format!("wgates-{generation}"),
            interface: format!("wgn{}", &generation[..10]),
            peer: format!("wgp{}", &generation[..10]),
            host,
            host6,
            peer6,
            endpoints,
            namespace_identity: None,
            namespace_file: None,
            firewall_digest: None,
            paused: false,
        };
        if self.record_path(generation).exists()
            || Path::new("/run/netns").join(&record.namespace).exists()
        {
            return Err(invalid(
                "native generation collides with retained resources; inspect before retrying",
            ));
        }
        self.save(&record)?;
        let result: io::Result<()> = (|| {
            self.create_network(&mut record)?;
            let instance = self.start(record.clone())?;
            self.instances.insert(generation.into(), instance);
            Ok(())
        })();
        if result.is_err() && self.cleanup(&mut record, true).is_err() {
            let mut auth = Authentication::new(Credentials::default(), false)?;
            auth.fail("native_cleanup_required");
            self.instances.insert(
                generation.into(),
                Instance {
                    record,
                    auth,
                    openvpn: None,
                    proxy: None,
                    listener: None,
                    management: None,
                    buffer: Vec::new(),
                    environment: None,
                    dns: None,
                    admitted_session: None,
                    proxy_gate: None,
                },
            );
            return Err(invalid(
                "native preparation failed; owned resources retained for guarded recovery",
            ));
        }
        result?;
        Ok(json!(record.prepared))
    }
    fn create_network(&self, record: &mut Record) -> io::Result<()> {
        if record.paused {
            return Ok(());
        }
        let generation = record.prepared.generation.clone();
        let generation = generation.as_str();
        let host = record.host;
        let IpAddr::V4(peer) = record.prepared.address else {
            return Err(invalid("invalid native bridge family"));
        };
        let host6 = record.host6;
        let peer6 = record.peer6;
        for family in ["-4", "-6"] {
            let routes: Value = serde_json::from_str(&command(
                "/usr/sbin/ip",
                &[family, "-j", "route", "show", "table", "all"],
            )?)?;
            let network = crate::policy::Network::parse(&if family == "-4" {
                format!("{host}/30")
            } else {
                format!("{host6}/64")
            })?;
            if routes.as_array().is_some_and(|a| {
                a.iter()
                    .filter_map(|r| r["dst"].as_str())
                    .filter_map(|r| crate::policy::Network::parse(r).ok())
                    .any(|r| r.contains(network.address) || network.contains(r.address))
            }) {
                return Err(invalid(
                    "native bridge conflicts with an existing host route; retain it for inspection",
                ));
            }
        }

        if Path::new("/run/netns").join(&record.namespace).exists() {
            return Err(invalid(
                "native namespace is already present; inspect ownership",
            ));
        }
        secure_directory(Path::new("/run/netns"), 0o755, 0o022)?;
        let namespace_path = Path::new("/run/netns").join(&record.namespace);
        private_text(&namespace_path, "")?;
        let original = fs::metadata(&namespace_path)?;
        record.namespace_file = Some((original.dev(), original.ino()));
        self.save(record)?;
        let target = CString::new(namespace_path.as_os_str().as_encoded_bytes())
            .map_err(|_| invalid("invalid namespace path"))?;
        let source = CString::new("/proc/self/ns/net").unwrap();
        let mut creator = Command::new("/usr/bin/true");
        creator
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the child only creates a network namespace and bind mount using fixed, live C strings before exec.
        unsafe {
            creator.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::unshare(libc::CLONE_NEWNET) != 0
                    || libc::mount(
                        source.as_ptr(),
                        target.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut creator = creator.spawn()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = creator.try_wait()? {
                if !status.success() {
                    return Err(invalid("native namespace creation failed"));
                }
                break;
            }
            if Instant::now() >= deadline {
                let _ = creator.kill();
                let _ = creator.wait();
                return Err(invalid("native namespace creation timed out"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let meta = fs::metadata(&namespace_path)?;
        record.namespace_identity = Some((meta.dev(), meta.ino()));
        self.save(record)?;
        command(
            "/usr/sbin/ip",
            &[
                "link",
                "add",
                &record.interface,
                "type",
                "veth",
                "peer",
                "name",
                &record.peer,
            ],
        )?;
        command(
            "/usr/sbin/ip",
            &["link", "set", &record.interface, "alias", generation],
        )?;
        command(
            "/usr/sbin/ip",
            &["link", "set", &record.peer, "netns", &record.namespace],
        )?;
        command(
            "/usr/sbin/ip",
            &[
                "address",
                "add",
                &format!("{host}/30"),
                "dev",
                &record.interface,
            ],
        )?;
        command("/usr/sbin/ip", &["link", "set", &record.interface, "up"])?;
        ns(
            record,
            &["address", "add", &format!("{peer}/30"), "dev", &record.peer],
        )?;
        ns(record, &["link", "set", &record.peer, "up"])?;
        ns(record, &["link", "set", "lo", "up"])?;
        command(
            "/usr/sbin/ip",
            &[
                "netns",
                "exec",
                &record.namespace,
                "/usr/sbin/sysctl",
                "-q",
                "-w",
                "net.ipv6.conf.all.disable_ipv6=0",
                "net.ipv6.conf.default.disable_ipv6=0",
            ],
        )?;
        command(
            "/usr/sbin/sysctl",
            &[
                "-q",
                "-w",
                &format!("net.ipv6.conf.{}.disable_ipv6=0", record.interface),
            ],
        )?;
        command(
            "/usr/sbin/ip",
            &[
                "-6",
                "address",
                "add",
                &format!("{host6}/64"),
                "dev",
                &record.interface,
                "nodad",
            ],
        )?;
        ns(
            record,
            &[
                "-6",
                "address",
                "add",
                &format!("{peer6}/64"),
                "dev",
                &record.peer,
                "nodad",
            ],
        )?;
        for endpoint in &record.endpoints {
            if endpoint.address.is_ipv4() {
                ns(
                    record,
                    &[
                        "route",
                        "add",
                        &format!("{}/32", endpoint.address),
                        "via",
                        &host.to_string(),
                        "dev",
                        &record.peer,
                    ],
                )?;
            } else {
                ns(
                    record,
                    &[
                        "-6",
                        "route",
                        "add",
                        &format!("{}/128", endpoint.address),
                        "via",
                        &host6.to_string(),
                        "dev",
                        &record.peer,
                    ],
                )?;
            }
        }
        self.firewall(record)?;
        record.firewall_digest = Some(nft_digest(&format!("wgates_{generation}"))?);
        self.save(record)?;
        Ok(())
    }
    fn firewall(&self, r: &mut Record) -> io::Result<()> {
        let mut forward = String::new();
        let mut output = String::new();
        let mut nat = String::new();
        for e in &r.endpoints {
            let family = if e.address.is_ipv4() { "ip" } else { "ip6" };
            let source = if e.address.is_ipv4() {
                r.prepared.address.to_string()
            } else {
                r.peer6.to_string()
            };
            forward += &format!(
                "iifname \"{}\" {family} saddr {source} {family} daddr {} {} dport {} accept; oifname \"{}\" {family} saddr {} {} sport {} ct state established,related accept;",
                r.interface,
                e.address,
                e.protocol,
                e.port,
                r.interface,
                e.address,
                e.protocol,
                e.port
            );
            output += &format!(
                "oifname \"{}\" meta skuid 0 {family} daddr {} {} dport {} accept;",
                r.peer, e.address, e.protocol, e.port
            );
            nat += &format!(
                "iifname \"{}\" {family} saddr {source} {family} daddr {} {} dport {} masquerade;",
                r.interface, e.address, e.protocol, e.port
            );
        }
        nft(
            None,
            &format!(
                "create table inet wgates_{}\ntable inet wgates_{} {{ comment \"{}\"; chain input {{ type filter hook input priority -10; iifname \"{}\" icmpv6 type {{nd-neighbor-solicit,nd-neighbor-advert}} accept; iifname \"{}\" ct state established,related accept; iifname \"{}\" drop; }}; chain forward {{ type filter hook forward priority -10; {forward} iifname \"{}\" drop; oifname \"{}\" drop; }}; chain nat {{ type nat hook postrouting priority srcnat; {nat} }}; }}",
                r.prepared.generation,
                r.prepared.generation,
                r.prepared.generation,
                r.interface,
                r.interface,
                r.interface,
                r.interface,
                r.interface
            ),
        )?;
        r.firewall_digest = Some(nft_digest(&format!("wgates_{}", r.prepared.generation))?);
        self.save(r)?;
        nft(
            Some(&r.namespace),
            &format!(
                "table inet wgates {{ comment \"{}\"; chain input {{ type filter hook input priority 0; policy drop; iifname lo accept; iifname \"wgates-tun\" accept; ip saddr {} tcp dport {{22100,22101}} accept; ct state established,related accept; icmpv6 type {{nd-neighbor-solicit,nd-neighbor-advert}} accept; }}; chain output {{ type filter hook output priority 0; policy drop; oifname lo accept; oifname \"wgates-tun\" accept; {output} oifname \"{}\" ip daddr {} tcp sport {{22100,22101}} ct state established accept; icmpv6 type {{nd-neighbor-solicit,nd-neighbor-advert}} accept; }}; }}",
                r.prepared.generation, r.host, r.peer, r.host
            ),
        )
    }
    fn start(&self, record: Record) -> io::Result<Instance> {
        let dir = self.directory.join(&record.prepared.generation);
        secure_directory(&dir, 0o700, 0o077)?;
        let socket = dir.join("management.sock");
        if socket.exists() {
            fs::remove_file(&socket)?;
        }
        let listener = UnixListener::bind(&socket)?;
        listener.set_nonblocking(true)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let auth_path = self.auth_path(&record);
        let (credentials, remembered) = match private_read(&auth_path, 32768) {
            Ok(bytes) => (
                serde_json::from_slice::<Credentials>(&bytes)
                    .map_err(|_| invalid("invalid saved native credentials"))?,
                true,
            ),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (Credentials::default(), false),
            Err(e) => return Err(e),
        };
        let auth = Authentication::new(credentials, remembered)?;
        let mut instance = Instance {
            record,
            auth,
            openvpn: None,
            proxy: None,
            listener: Some(listener),
            management: None,
            buffer: Vec::new(),
            environment: None,
            dns: None,
            admitted_session: None,
            proxy_gate: None,
        };
        if !instance.record.paused {
            let profile = profile(&instance.record.profile)?;
            let mut text = String::new();
            for option in profile.options.iter().filter(|o| {
                !matches!(
                    o[0].as_str(),
                    "dev"
                        | "remote"
                        | "proto"
                        | "port"
                        | "verb"
                        | "mute"
                        | "nobind"
                        | "remote-random-hostname"
                )
            }) {
                text += &option
                    .iter()
                    .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
                    .collect::<Vec<_>>()
                    .join(" ");
                text.push('\n');
            }
            for endpoint in &instance.record.endpoints {
                text += &format!(
                    "remote {} {} {}{}\n",
                    endpoint.address,
                    endpoint.port,
                    if endpoint.protocol == "tcp" {
                        "tcp"
                    } else {
                        "udp"
                    },
                    if endpoint.address.is_ipv4() {
                        if endpoint.protocol == "tcp" {
                            "4-client"
                        } else {
                            "4"
                        }
                    } else if endpoint.protocol == "tcp" {
                        "6-client"
                    } else {
                        "6"
                    }
                );
            }
            for (kind, data) in &profile.inline {
                text += &format!("<{kind}>\n{data}\n</{kind}>\n");
            }
            if !profile.options.iter().any(|o| o[0] == "remote-cert-tls") {
                text += "remote-cert-tls server\n";
            }
            text += &format!(
                "dev wgates-tun\ndev-type tun\nnobind\nscript-security 1\nallow-compression no\ndisable-dco\nauth-retry interact\nauth-nocache\nverb 3\nmanagement {} unix\nmanagement-client\nmanagement-hold\nmanagement-query-passwords\nmanagement-up-down\nup-restart\nmanagement-log-cache 1\nsetenv IV_SSO webauth,openurl,crtext\n",
                socket
                    .to_str()
                    .ok_or_else(|| invalid("invalid native runtime path"))?
            );
            let path = dir.join("openvpn.conf");
            if path.exists() {
                fs::remove_file(&path)?;
            }
            private_text(&path, &text)?;
            instance.openvpn = Some(namespace_child(
                &instance.record,
                Path::new("/usr/sbin/openvpn"),
                &["--config", path.to_str().unwrap()],
                Stdio::null(),
                None,
            )?);
        } else {
            instance.auth.state = "stopped".into();
            instance.auth.reason = "operator_stopped".into();
        }
        Ok(instance)
    }
    fn proxy(&self, instance: &mut Instance, gate: bool) -> io::Result<()> {
        if instance.proxy_gate == Some(gate)
            && instance
                .proxy
                .as_mut()
                .is_some_and(|p| p.try_wait().ok().flatten().is_none())
        {
            return Ok(());
        }
        stop(&mut instance.proxy);
        let p = &instance.record.prepared;
        let inbounds = [("data", p.data_port, false), ("diagnostic", p.probe_port, true)].into_iter().map(|(tag, port, diagnostic)| json!({"tag":tag,"listen":p.address.to_string(),"port":port,"protocol":"vless","settings":{"clients":[{"id":p.bridge_id(diagnostic)}],"decryption":"none"},"streamSettings":{"network":"raw","security":"none"}})).collect::<Vec<_>>();
        let value = json!({"log":{"loglevel":"none"},"inbounds":inbounds,"outbounds":[{"tag":"tunnel","protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["0.0.0.0/0","::/0"]}]}},{"tag":"block","protocol":"blackhole"}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","domain":["regexp:.+"],"outboundTag":"block"},{"type":"field","inboundTag":["data"],"outboundTag":if gate{"tunnel"}else{"block"}}]}});
        let path = self.directory.join(&p.generation).join("proxy.json");
        private_write(&path, &value)?;
        instance.proxy = Some(namespace_child(
            &instance.record,
            &self.xray,
            &["run", "-config", "stdin:"],
            Stdio::from(File::open(&path)?),
            Some((self.uid, self.gid)),
        )?);
        instance.proxy_gate = Some(gate);
        Ok(())
    }
    fn cleanup(&self, record: &mut Record, forget: bool) -> io::Result<()> {
        let table = format!("wgates_{}", record.prepared.generation);
        let tables: Value =
            serde_json::from_str(&command("/usr/sbin/nft", &["-j", "list", "tables"])?)?;
        let present = tables["nftables"].as_array().is_some_and(|a| {
            a.iter()
                .any(|v| v["table"]["family"] == "inet" && v["table"]["name"] == table)
        });
        if present {
            let actual = nft_digest(&table)?;
            if record.firewall_digest.as_ref() != Some(&actual) {
                return Err(invalid(
                    "owned native firewall changed or ownership is uncertain; retain resources for inspection",
                ));
            }
            nft(None, &format!("delete table inet {table}"))?;
        }
        record.firewall_digest = None;
        self.save(record)?;
        let ns_path = Path::new("/run/netns").join(&record.namespace);
        if ns_path.exists() {
            let meta = fs::symlink_metadata(&ns_path)?;
            let identity = (meta.dev(), meta.ino());
            if record.namespace_identity == Some(identity) {
                let path = CString::new(ns_path.as_os_str().as_encoded_bytes())
                    .map_err(|_| invalid("invalid namespace path"))?;
                // SAFETY: fresh metadata confirms this exact owned namespace mount before detaching it.
                if unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            } else if record.namespace_file != Some(identity) {
                return Err(invalid(
                    "native namespace ownership is uncertain; inspect retained resources",
                ));
            }
            let meta = fs::symlink_metadata(&ns_path)?;
            if record.namespace_file != Some((meta.dev(), meta.ino()))
                || !meta.is_file()
                || meta.uid() != 0
                || meta.nlink() != 1
            {
                return Err(invalid(
                    "native namespace file changed; retain it for inspection",
                ));
            }
            fs::remove_file(&ns_path)?;
        }
        record.namespace_identity = None;
        record.namespace_file = None;
        self.save(record)?;
        let links: Value =
            serde_json::from_str(&command("/usr/sbin/ip", &["-d", "-j", "link", "show"])?)?;
        if let Some(link) = links
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["ifname"] == record.interface)
        {
            if link["ifalias"] != record.prepared.generation {
                return Err(invalid(
                    "native link ownership changed; retain it for inspection",
                ));
            }
            let deletion = command("/usr/sbin/ip", &["link", "delete", &record.interface]);
            let remaining: Value =
                serde_json::from_str(&command("/usr/sbin/ip", &["-j", "link", "show"])?)?;
            if remaining
                .as_array()
                .is_none_or(|links| links.iter().any(|link| link["ifname"] == record.interface))
            {
                return Err(deletion
                    .err()
                    .unwrap_or_else(|| invalid("native link removal could not be confirmed")));
            }
        }
        let dir = self.directory.join(&record.prepared.generation);
        if dir.exists() {
            secure_directory(&dir, 0o700, 0o077)?;
            for file in fs::read_dir(&dir)? {
                let path = file?.path();
                if !matches!(
                    path.file_name().and_then(|n| n.to_str()),
                    Some("management.sock" | "openvpn.conf" | "proxy.json")
                ) {
                    return Err(invalid("unknown native runtime file retained"));
                }
                let m = fs::symlink_metadata(&path)?;
                if m.uid() != 0 || m.file_type().is_symlink() {
                    return Err(invalid("native runtime ownership changed"));
                }
                fs::remove_file(path)?;
            }
            fs::remove_dir(dir)?;
        }
        record.namespace_identity = None;
        if forget {
            if !self.instances.values().any(|i| {
                i.record.prepared.id == record.prepared.id
                    && i.record.prepared.profile_digest == record.prepared.profile_digest
            }) {
                let auth = self.auth_path(record);
                if auth.exists() {
                    private_read(&auth, 32768)?;
                    fs::remove_file(auth)?;
                }
            }
            fs::remove_file(self.record_path(&record.prepared.generation))?;
            File::open(&self.root)?.sync_all()?;
        } else {
            self.save(record)?;
        }
        Ok(())
    }
    fn observation(instance: &Instance) -> Observation {
        Observation {
            session: instance.auth.session.clone(),
            authentication: instance.auth.state.clone(),
            reason: instance.auth.reason.clone(),
            dns: instance.dns.clone(),
            admitted: instance.admitted_session.as_ref() == Some(&instance.auth.session),
            resources_active: instance.record.namespace_identity.is_some()
                || instance.openvpn.is_some()
                || instance.proxy.is_some(),
            expires_at: instance.auth.expires_at,
            remembered: instance.auth.remembered,
        }
    }
    fn poll(&mut self) {
        let keys: Vec<_> = self.instances.keys().cloned().collect();
        for key in keys {
            let mut instance = self.instances.remove(&key).unwrap();
            let result = self.poll_instance(&mut instance);
            if let Err(error) = result {
                instance.auth.fail("native_runtime_failed");
                instance.auth.reason = error.to_string();
                instance.dns = None;
                instance.admitted_session = None;
                stop(&mut instance.proxy);
                instance.proxy_gate = None;
                stop(&mut instance.openvpn);
                instance.management = None;
            }
            self.instances.insert(key, instance);
        }
    }
    fn poll_instance(&self, i: &mut Instance) -> io::Result<()> {
        if let Some(reason) = child_diagnostic(&mut i.openvpn)?.or(child_diagnostic(&mut i.proxy)?)
        {
            i.auth.reason = reason.into();
        }

        if i.auth.expire() {
            i.dns = None;
            i.admitted_session = None;
            stop(&mut i.proxy);
            i.proxy_gate = None;
            stop(&mut i.openvpn);
            i.management = None;
        }
        if let Some(child) = i.proxy.as_mut()
            && child.try_wait()?.is_some()
        {
            return Err(invalid("native proxy exited"));
        }
        if let Some(child) = i.openvpn.as_mut()
            && child.try_wait()?.is_some()
        {
            i.openvpn = None;
            i.auth.fail("native_client_exited");
            i.dns = None;
            i.admitted_session = None;
            stop(&mut i.proxy);
            i.proxy_gate = None;
            i.management = None;
        }
        if i.management.is_none()
            && i.openvpn.is_some()
            && let Some(listener) = &i.listener
        {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(true)?;
                    stream.write_all(b"state on\nlog off\necho off\nhold off\nhold release\n")?;
                    i.management = Some(stream);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        let mut lines = Vec::new();
        if let Some(stream) = i.management.as_mut() {
            let mut chunk = [0; 4096];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => return Err(invalid("native management disconnected")),
                    Ok(n) => {
                        i.buffer.extend_from_slice(&chunk[..n]);
                        if i.buffer.len() > 256 * 1024 {
                            return Err(invalid("native management buffer exceeded"));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            while let Some(end) = i.buffer.iter().position(|b| *b == b'\n') {
                let line = String::from_utf8(i.buffer.drain(..=end).collect())
                    .map_err(|_| invalid("invalid native management encoding"))?;
                lines.push(line.trim_end_matches(['\n', '\r']).to_owned());
            }
        }
        for line in lines {
            let old = i.auth.session.clone();
            let commands = i.auth.receive(&line)?;
            for command in commands {
                if let Some(stream) = i.management.as_mut() {
                    stream.write_all(command.as_bytes())?;
                    stream.write_all(b"\n")?;
                }
            }
            if old != i.auth.session || i.auth.state != "authenticated" {
                i.admitted_session = None;
            }
            if line == ">UPDOWN:UP" {
                i.environment = Some(BTreeMap::new());
            } else if line == ">UPDOWN:DOWN" {
                i.dns = None;
                i.admitted_session = None;
                stop(&mut i.proxy);
                i.proxy_gate = None;
            } else if let Some(value) = line.strip_prefix(">UPDOWN:ENV,") {
                if value == "END" {
                    if let Some(environment) = i.environment.take() {
                        let dns = pushed_dns(&environment)?;
                        if i.dns.is_some() && i.dns != dns {
                            i.auth.session = random_id()?;
                            i.admitted_session = None;
                        }
                        i.dns = dns;
                    }
                } else if let Some((key, value)) = value.split_once('=')
                    && (key.starts_with("foreign_option_") || key.starts_with("dns_server_"))
                    && let Some(environment) = i.environment.as_mut()
                {
                    if environment.len() >= 256 {
                        return Err(invalid("native environment limit exceeded"));
                    }
                    environment.insert(key.into(), value.into());
                }
            }
        }
        if i.auth.state == "authenticated" {
            self.proxy(i, i.admitted_session.as_ref() == Some(&i.auth.session))?;
        } else if i.proxy.is_some() {
            stop(&mut i.proxy);
            i.proxy_gate = None;
        }
        Ok(())
    }
    fn dispatch(&mut self, request: &Value) -> io::Result<Value> {
        let command = request["command"]
            .as_str()
            .ok_or_else(|| invalid("native command required"))?;
        let fields: &[&str] = match command {
            "preflight" | "list" => &[],
            "prepare" => &["id", "generation", "profile"],
            "state" | "logout" | "restart" | "forget-auth" | "release" => &["generation"],
            "login" => &["generation", "credentials", "remember"],
            "admit" => &["generation", "session", "admitted"],
            _ => return Err(invalid("unsupported native command")),
        };
        if request.as_object().is_none_or(|m| {
            m.keys()
                .any(|k| k != "api_version" && k != "command" && !fields.contains(&k.as_str()))
        }) {
            return Err(invalid("unexpected native request field"));
        }
        if request.get("remember").is_some_and(|v| !v.is_boolean()) {
            return Err(invalid("native remember boolean required"));
        }
        if command == "preflight" {
            return self.preflight();
        }
        if command == "list" {
            return Ok(json!(
                self.instances
                    .values()
                    .map(
                        |i| json!({"prepared":i.record.prepared,"observation":Self::observation(i)})
                    )
                    .collect::<Vec<_>>()
            ));
        }
        let generation = request["generation"]
            .as_str()
            .filter(|s| valid_generation(s))
            .ok_or_else(|| invalid("invalid native generation"))?;
        if command == "prepare" {
            return self.prepare(
                request["id"].as_str().unwrap_or(""),
                generation,
                &request["profile"],
            );
        }
        let mut i = self
            .instances
            .remove(generation)
            .ok_or_else(|| invalid("native generation is not prepared"))?;
        let result = (|| match command {
            "state" => {
                Ok(json!({"prepared":i.record.prepared,"observation":Self::observation(&i)}))
            }
            "login" => {
                if i.record.paused || i.openvpn.is_none() {
                    i.record.paused = false;
                    self.save(&i.record)?;
                    stop(&mut i.proxy);
                    stop(&mut i.openvpn);
                    i.listener = None;
                    if i.record.namespace_identity.is_none() {
                        self.create_network(&mut i.record)?;
                    }
                    i = self.start(i.record.clone())?;
                }
                if let Some(credentials) = request.get("credentials") {
                    let remember = request["remember"].as_bool().unwrap_or(false);
                    let was_remembered = i.auth.remembered;
                    let commands = i.auth.submit(credentials, remember)?;
                    let stream = i.management.as_mut().ok_or_else(|| {
                        invalid("native authentication not ready; inspect login state")
                    })?;
                    for command in commands {
                        stream.write_all(command.as_bytes())?;
                        stream.write_all(b"\n")?;
                    }
                    if remember
                        && let Err(error) =
                            private_write(&self.auth_path(&i.record), &i.auth.credentials)
                    {
                        i.auth.remembered = was_remembered;
                        return Err(error);
                    }
                }
                Ok(i.auth.action())
            }
            "admit" => {
                let admitted = request["admitted"]
                    .as_bool()
                    .ok_or_else(|| invalid("native admission boolean required"))?;
                if admitted
                    && (request["session"].as_str() != Some(&i.auth.session)
                        || i.auth.state != "authenticated")
                {
                    return Err(invalid(
                        "native session changed; repeat resource verification",
                    ));
                }
                i.admitted_session = if admitted {
                    Some(i.auth.session.clone())
                } else {
                    None
                };
                if i.auth.state == "authenticated" {
                    self.proxy(&mut i, admitted)?;
                }
                Ok(json!(Self::observation(&i)))
            }
            "logout" => {
                i.record.paused = true;
                self.save(&i.record)?;
                stop(&mut i.proxy);
                stop(&mut i.openvpn);
                i.management = None;
                let remembered = i.auth.remembered;
                i.auth.forget();
                i.auth.fail("operator_stopped");
                i.auth.remembered = remembered;
                i.auth.state = "stopped".into();
                i.dns = None;
                i.admitted_session = None;
                i.proxy_gate = None;
                i.listener = None;
                self.cleanup(&mut i.record, false)?;
                Ok(json!(Self::observation(&i)))
            }
            "restart" => {
                i.record.paused = false;
                self.save(&i.record)?;
                stop(&mut i.proxy);
                stop(&mut i.openvpn);
                i.management = None;
                if i.record.namespace_identity.is_none() {
                    self.create_network(&mut i.record)?;
                }
                i = self.start(i.record.clone())?;
                Ok(json!(Self::observation(&i)))
            }
            "forget-auth" => {
                let prefix = format!("{}-", i.record.prepared.id);
                for file in fs::read_dir(&self.root)? {
                    let path = file?.path();
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if let Some(digest) = name
                        .strip_prefix(&prefix)
                        .and_then(|n| n.strip_suffix(".auth"))
                        && digest.len() == 64
                        && digest
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    {
                        private_read(&path, 32768)?;
                        fs::remove_file(path)?;
                    }
                }
                File::open(&self.root)?.sync_all()?;
                i.auth.forget();
                if let Some(stream) = i.management.as_mut() {
                    stream.write_all(b"forget-passwords\n")?;
                }
                for other in self
                    .instances
                    .values_mut()
                    .filter(|other| other.record.prepared.id == i.record.prepared.id)
                {
                    other.auth.forget();
                    if let Some(stream) = other.management.as_mut() {
                        stream.write_all(b"forget-passwords\n")?;
                    }
                }
                Ok(json!({"forgotten":true}))
            }
            "release" => {
                i.admitted_session = None;
                i.proxy_gate = None;
                i.auth.fail("native_cleanup_required");
                stop(&mut i.proxy);
                stop(&mut i.openvpn);
                i.management = None;
                self.cleanup(&mut i.record, true)?;
                Ok(json!({"released":true}))
            }
            _ => unreachable!(),
        })();
        if command != "release" || result.is_err() {
            self.instances.insert(generation.into(), i);
        }
        result
    }
}
fn pushed_dns(environment: &BTreeMap<String, String>) -> io::Result<Option<String>> {
    let mut candidates = Vec::new();
    for (key, value) in environment {
        if let Some((priority, address)) = key
            .strip_prefix("dns_server_")
            .and_then(|key| key.split_once("_address_"))
            && let (Ok(priority), Ok(address)) = (priority.parse::<i32>(), address.parse::<u32>())
        {
            candidates.push(((0, i64::from(priority), address), value.as_str()));
        } else if let Some(index) = key
            .strip_prefix("foreign_option_")
            .and_then(|index| index.parse::<u32>().ok())
        {
            let fields: Vec<_> = value.split_whitespace().collect();
            if fields.len() == 3
                && fields[0] == "dhcp-option"
                && matches!(fields[1], "DNS" | "DNS6")
            {
                candidates.push(((1, i64::from(index), 0), fields[2]));
            }
        }
    }
    candidates.sort_by_key(|(order, _)| *order);
    for (_, value) in candidates {
        if let Ok(ip) = value.parse::<IpAddr>()
            && let Ok(resolver) = crate::policy::Resolver::parse(&format!(
                "udp://{}",
                std::net::SocketAddr::new(ip, 53)
            ))
        {
            return Ok(Some(resolver.canonical()));
        }
    }
    Ok(None)
}

fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut value: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: value and length are valid writable buffers for SO_PEERCRED on this live stream.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut value as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(value.uid)
}
pub fn run(mut args: impl Iterator<Item = OsString>, cleanup_only: bool) -> io::Result<()> {
    // SAFETY: geteuid takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return Err(invalid("native runtime requires root"));
    }
    let mut socket = PathBuf::from(crate::native::DEFAULT_SOCKET);
    let mut root = PathBuf::from("/var/lib/wgates-native");
    let mut xray = None;
    let mut user = "wgates".to_owned();
    while let Some(arg) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| invalid("native option requires a value"))?;
        match arg.to_str() {
            Some("--socket") => socket = value.into(),
            Some("--state-dir") => root = value.into(),
            Some("--xray-bin") => xray = Some(PathBuf::from(value)),
            Some("--service-user") => {
                user = value
                    .into_string()
                    .map_err(|_| invalid("invalid service user"))?
            }
            _ => return Err(invalid("unknown native runtime option")),
        }
    }
    if !socket.is_absolute() || !root.is_absolute() {
        return Err(invalid("native paths must be absolute"));
    }
    root = controlled_path(&root)?;
    let parent = controlled_path(
        socket
            .parent()
            .ok_or_else(|| invalid("native socket parent required"))?,
    )?;
    socket = parent.join(
        socket
            .file_name()
            .ok_or_else(|| invalid("native socket name required"))?,
    );
    if !cleanup_only {
        match fs::symlink_metadata(&socket) {
            Ok(_) => {
                return Err(invalid(
                    "native socket path is occupied; stop its owner or inspect the stale socket",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let (uid, gid) = if cleanup_only {
        (
            0,
            fs::symlink_metadata(
                socket
                    .parent()
                    .ok_or_else(|| invalid("native socket parent required"))?,
            )
            .map(|m| m.gid())
            .unwrap_or(0),
        )
    } else {
        let user = CString::new(user).map_err(|_| invalid("invalid service user"))?;
        // SAFETY: getpwnam returns a libc-owned record; numeric fields are copied before another call.
        let account = unsafe { libc::getpwnam(user.as_ptr()) };
        if account.is_null() {
            return Err(invalid("native service user does not exist"));
        }
        // SAFETY: the non-null account pointer remains valid through this copy.
        unsafe { ((*account).pw_uid, (*account).pw_gid) }
    };
    secure_directory(&root, 0o700, 0o077)?;
    let lock = File::open(&root)?;
    // SAFETY: lock stays open throughout the helper lifetime.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(invalid("native state already in use"));
    }
    let directory = socket
        .parent()
        .ok_or_else(|| invalid("native socket parent required"))?
        .to_owned();
    if !directory.exists() {
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o750))?;
        let path = CString::new(directory.as_os_str().as_encoded_bytes())
            .map_err(|_| invalid("invalid native directory"))?;
        // SAFETY: path is a valid NUL-terminated owned directory path.
        if unsafe { libc::chown(path.as_ptr(), 0, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != gid
        || metadata.mode() & 0o027 != 0
    {
        return Err(invalid(
            "native socket directory must be root-owned with the service group",
        ));
    }
    for binary in ["/usr/sbin/ip", "/usr/sbin/nft"] {
        executable(Path::new(binary))?;
    }
    let xray = xray.unwrap_or_else(|| {
        PathBuf::from(if cfg!(target_arch = "aarch64") {
            "/usr/local/x-ui/bin/xray-linux-arm64"
        } else {
            "/usr/local/x-ui/bin/xray-linux-amd64"
        })
    });
    let xray = if cleanup_only {
        xray
    } else {
        executable(&xray)?
    };
    let mut runtime = Runtime {
        root,
        directory,
        uid,
        gid,
        xray,
        instances: BTreeMap::new(),
    };
    let mut retained = Vec::new();
    for entry in fs::read_dir(&runtime.root)? {
        let path = entry?.path();
        if path.extension().is_some_and(|s| s == "json")
            && path
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(valid_generation)
        {
            let record: Record = serde_json::from_slice(&private_read(&path, 2 * 1024 * 1024)?)
                .map_err(|_| invalid("invalid retained native state"))?;
            if path != runtime.record_path(&record.prepared.generation)
                || !valid_id(&record.prepared.id)
                || !valid_generation(&record.prepared.generation)
            {
                return Err(invalid("invalid native state identity"));
            }
            record.validate()?;
            retained.push(record);
        }
    }
    for record in &mut retained {
        runtime.cleanup(record, false)?;
    }
    if cleanup_only {
        return Ok(());
    }
    runtime.preflight()?;
    for mut record in retained {
        runtime.create_network(&mut record)?;
        let instance = runtime.start(record)?;
        runtime
            .instances
            .insert(instance.record.prepared.generation.clone(), instance);
    }
    let listener = UnixListener::bind(&socket)?;
    let metadata = fs::symlink_metadata(&socket)?;
    let owned_socket = crate::OwnedSocket {
        path: socket.clone(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660))?;
    let cpath = CString::new(socket.as_os_str().as_encoded_bytes())
        .map_err(|_| invalid("invalid native socket"))?;
    // SAFETY: cpath names this helper's newly bound socket.
    if unsafe { libc::chown(cpath.as_ptr(), 0, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    listener.set_nonblocking(true)?;
    if let Some(address) = std::env::var_os("NOTIFY_SOCKET") {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::net::{SocketAddr, UnixDatagram};
        let notification = UnixDatagram::unbound()?;
        if let Some(name) = address.as_bytes().strip_prefix(b"@") {
            notification.connect_addr(&SocketAddr::from_abstract_name(name)?)?;
        } else {
            notification.connect(Path::new(&address))?;
        }
        notification.send(b"READY=1")?;
    }
    let stopping = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(libc::SIGTERM, stopping.clone())?;
    signal_hook::flag::register(libc::SIGINT, stopping.clone())?;
    while !stopping.load(Ordering::Relaxed) {
        runtime.poll();
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false)?;
                let response = if ![0, uid].contains(&peer_uid(&stream)?) {
                    json!({"api_version":1,"error":"native peer is not authorized"})
                } else {
                    match read_message(&mut stream) {
                        Ok(request) if request["api_version"] == API_VERSION => {
                            match runtime.dispatch(&request) {
                                Ok(data) => json!({"api_version":1,"data":data}),
                                Err(error) => json!({"api_version":1,"error":error.to_string()}),
                            }
                        }
                        _ => json!({"api_version":1,"error":"invalid native request"}),
                    }
                };
                let _ = write_message(&mut stream, &response);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(e) => return Err(e),
        }
    }
    let keys: Vec<_> = runtime.instances.keys().cloned().collect();
    let mut failed = false;
    for key in keys {
        let mut i = runtime.instances.remove(&key).unwrap();
        stop(&mut i.proxy);
        stop(&mut i.openvpn);
        i.management = None;
        if let Err(error) = runtime.cleanup(&mut i.record, false) {
            eprintln!("wgates: native cleanup: {error}");
            failed = true;
        }
    }
    owned_socket.cleanup()?;
    if failed {
        return Err(invalid("native resources retained for guarded cleanup"));
    }
    Ok(())
}
