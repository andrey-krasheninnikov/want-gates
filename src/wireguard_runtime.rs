use super::{Endpoint, Record, command, executable, namespace_child, ns};
use crate::invalid;
use crate::policy::Network;
use crate::wireguard::{Profile, decoded_profile, endpoint, unicast};
use serde_json::Value;
use std::fs::{File, Permissions};
use std::io::{self, Seek, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::FromRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

const WG: &str = "/usr/bin/wg";
const INTERFACE: &str = "wgates-tun";
pub(super) const MARK: &str = "51820";

pub(super) fn version() -> io::Result<String> {
    let path = executable(Path::new(WG)).map_err(|_| {
        invalid("WireGuard requires the root-controlled wireguard-tools executable /usr/bin/wg")
    })?;
    let output = command(
        path.to_str()
            .ok_or_else(|| invalid("invalid WireGuard executable path"))?,
        &["--version"],
    )?;
    output
        .lines()
        .next()
        .filter(|line| line.starts_with("wireguard-tools v"))
        .map(str::to_owned)
        .ok_or_else(|| invalid("unrecognized wireguard-tools version"))
}

pub(super) fn resolve(profile: &Profile) -> io::Result<Endpoint> {
    let (host, port) = endpoint(&profile.endpoint)?;
    let address: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => command("/usr/bin/getent", &["-s", "files", "ahosts", &host])
            .or_else(|_| command("/usr/bin/getent", &["ahosts", &format!("{host}.")]))
            .map_err(|_| invalid("WireGuard endpoint bootstrap resolution failed"))?
            .lines()
            .filter_map(|line| line.split_whitespace().next()?.parse().ok())
            .find(|ip| unicast(*ip))
            .ok_or_else(|| invalid("WireGuard endpoint has no supported unicast address"))?,
    };
    Ok(Endpoint {
        address,
        port,
        protocol: "udp".into(),
    })
}

pub(super) fn validate_endpoints(record: &Record, profile: &Profile) -> io::Result<()> {
    let (host, port) = endpoint(&profile.endpoint)?;
    if !matches!(&record.endpoints[..], [e]
        if e.protocol == "udp" && e.port == port
            && host.parse::<IpAddr>().ok().is_none_or(|ip| ip == e.address))
    {
        return Err(invalid("invalid pinned WireGuard endpoint"));
    }
    let bridge = [
        Network::parse(&format!("{}/30", record.host))?,
        Network::parse(&format!("{}/64", record.host6))?,
    ];
    let conflicts = |address| bridge.iter().any(|network| network.contains(address));
    let pinned = record.endpoints[0].address;
    if conflicts(pinned)
        || profile.addresses.iter().any(|address| {
            address
                .split_once('/')
                .and_then(|(ip, _)| ip.parse().ok())
                .is_some_and(|address| conflicts(address) || address == pinned)
        })
    {
        return Err(invalid(
            "WireGuard tunnel address conflicts with its bridge or pinned endpoint",
        ));
    }
    Ok(())
}

pub(super) fn transport_route(record: &Record) -> io::Result<()> {
    let address = record.endpoints[0].address;
    let (family, destination, gateway) = if address.is_ipv4() {
        // Reverse lookup of an unmarked reply could select the tunnel in a full-tunnel profile.
        command(
            "/usr/sbin/ip",
            &[
                "netns",
                "exec",
                &record.namespace,
                "/usr/sbin/sysctl",
                "-q",
                "-w",
                "net.ipv4.conf.all.rp_filter=0",
                &format!("net.ipv4.conf.{}.rp_filter=0", record.peer),
            ],
        )?;
        ("-4", format!("{address}/32"), record.host.to_string())
    } else {
        ("-6", format!("{address}/128"), record.host6.to_string())
    };
    ns(
        record,
        &[
            family,
            "route",
            "add",
            &destination,
            "via",
            &gateway,
            "dev",
            &record.peer,
            "onlink",
            "table",
            MARK,
        ],
    )?;
    ns(
        record,
        &[
            family, "rule", "add", "priority", "100", "fwmark", MARK, "table", MARK,
        ],
    )?;
    ns(
        record,
        &[
            family,
            "rule",
            "add",
            "priority",
            "101",
            "fwmark",
            MARK,
            "unreachable",
        ],
    )?;
    Ok(())
}

fn setconf(record: &Record, profile: &Profile) -> io::Result<()> {
    let path = executable(Path::new(WG))?;
    let peer = &record.endpoints[0];
    let endpoint = SocketAddr::new(peer.address, peer.port);
    // The client reads the config from an anonymous file passed as stdin.
    // SAFETY: the static name is valid and a successful call transfers ownership of the fd.
    let fd = unsafe { libc::memfd_create(c"wgates-wireguard-config".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this process owns the newly created fd.
    let mut config = unsafe { File::from_raw_fd(fd) };
    config.set_permissions(Permissions::from_mode(0o600))?;
    write!(
        config,
        "[Interface]\nPrivateKey = {}\nFwMark = {MARK}\n\n[Peer]\nPublicKey = {}\nEndpoint = {endpoint}\nAllowedIPs = {}\n",
        profile.private_key,
        profile.public_key,
        profile.allowed_ips.join(", ")
    )?;
    if let Some(key) = &profile.preshared_key {
        writeln!(config, "PresharedKey = {key}")?;
    }
    if let Some(keepalive) = profile.keepalive {
        writeln!(config, "PersistentKeepalive = {keepalive}")?;
    }
    config.rewind()?;

    let mut child = namespace_child(
        record,
        &path,
        &["setconf", INTERFACE, "/dev/stdin"],
        Stdio::from(config),
        None,
        None,
    )?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) => return Err(invalid("WireGuard rejected the native configuration")),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(invalid("WireGuard configuration timed out"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let peer = command(
        "/usr/sbin/ip",
        &[
            "netns",
            "exec",
            &record.namespace,
            path.to_str()
                .ok_or_else(|| invalid("invalid WireGuard executable path"))?,
            "show",
            INTERFACE,
            "peers",
        ],
    )?;
    if peer.trim() != profile.public_key {
        return Err(invalid("WireGuard did not install the configured peer"));
    }
    Ok(())
}

fn endpoint_mtu(record: &Record) -> Option<u64> {
    let endpoint = &record.endpoints[0];
    let (family, source) = if endpoint.address.is_ipv4() {
        ("-4", record.prepared.address)
    } else {
        ("-6", IpAddr::V6(record.peer6))
    };
    let route: Vec<Value> = serde_json::from_str(
        &command(
            "/usr/sbin/ip",
            &[
                family,
                "-j",
                "route",
                "get",
                &endpoint.address.to_string(),
                "from",
                &source.to_string(),
                "iif",
                &record.interface,
                "ipproto",
                "udp",
                "dport",
                &endpoint.port.to_string(),
            ],
        )
        .ok()?,
    )
    .ok()?;
    let route = route.first()?;
    let device = route["dev"].as_str()?;
    let links: Vec<Value> = serde_json::from_str(
        &command("/usr/sbin/ip", &["-j", "link", "show", "dev", device]).ok()?,
    )
    .ok()?;
    let link_mtu = links.first()?.get("mtu")?.as_u64()?;
    route["metrics"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|metric| metric["mtu"].as_u64())
        .chain(std::iter::once(link_mtu))
        .min()
}

pub(super) fn start(record: &Record) -> io::Result<Option<String>> {
    let profile = decoded_profile(&record.profile)?;
    ns(
        record,
        &["link", "add", "dev", INTERFACE, "type", "wireguard"],
    )
    .map_err(|_| {
        invalid("cannot create the isolated WireGuard interface; check kernel WireGuard support")
    })?;
    ns(
        record,
        &["link", "set", "dev", INTERFACE, "addrgenmode", "none"],
    )?;
    let mtu = profile.mtu.map(u64::from).unwrap_or_else(|| {
        let minimum = if profile
            .addresses
            .iter()
            .any(|address| address.contains(':'))
        {
            1280
        } else {
            68
        };
        // Budget for IPv6 encapsulation while retaining the inner IP family's minimum MTU.
        endpoint_mtu(record)
            .unwrap_or(1500)
            .saturating_sub(80)
            .clamp(minimum, 1420)
    });
    ns(
        record,
        &["link", "set", "dev", INTERFACE, "mtu", &mtu.to_string()],
    )?;
    for address in &profile.addresses {
        if address.contains(':') {
            ns(
                record,
                &[
                    "-6",
                    "address",
                    "add",
                    address,
                    "dev",
                    INTERFACE,
                    "noprefixroute",
                    "nodad",
                ],
            )?;
        } else {
            ns(
                record,
                &[
                    "-4",
                    "address",
                    "add",
                    address,
                    "dev",
                    INTERFACE,
                    "noprefixroute",
                ],
            )?;
        }
    }
    setconf(record, &profile)?;
    ns(record, &["link", "set", "dev", INTERFACE, "up"])?;
    for cidr in &profile.allowed_ips {
        let v6 = cidr.contains(':');
        if profile
            .addresses
            .iter()
            .any(|address| address.contains(':') == v6)
        {
            ns(
                record,
                &[
                    if v6 { "-6" } else { "-4" },
                    "route",
                    "add",
                    cidr,
                    "dev",
                    INTERFACE,
                ],
            )?;
        }
    }
    Ok(profile
        .dns
        .map(|ip| format!("udp://{}", SocketAddr::new(ip, 53))))
}
