use crate::{invalid, store::MAX_PROFILE};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub options: Vec<Vec<String>>,
    pub inline: BTreeMap<String, String>,
}

const FILES: &[&str] = &[
    "ca",
    "cert",
    "key",
    "extra-certs",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "crl-verify",
    "pkcs12",
];

pub fn parse(input: &str) -> io::Result<Value> {
    if input.len() > MAX_PROFILE {
        return Err(invalid("profile exceeds 1 MiB"));
    }
    let profile = if input.trim_start().starts_with('{') {
        let mut value = crate::profile::strict_json(input)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| invalid("invalid OpenVPN profile"))?;
        if object.remove("protocol") != Some(json!("openvpn")) {
            return Err(invalid("invalid OpenVPN protocol"));
        }
        serde_json::from_value::<Profile>(value).map_err(|_| invalid("invalid OpenVPN profile"))?
    } else {
        package(source(input)?, None)?
    };
    validate(&profile)?;
    let mut value = serde_json::to_value(profile)?;
    value["protocol"] = json!("openvpn");
    if serde_json::to_vec(&value)?.len() > MAX_PROFILE {
        return Err(invalid("profile exceeds 1 MiB after packaging"));
    }
    Ok(value)
}

pub fn bundle(input: &str, directory: Option<&std::path::Path>) -> io::Result<String> {
    if input.trim_start().starts_with('{') {
        return parse(input).map(|v| v.to_string());
    }
    let profile = package(source(input)?, directory)?;
    validate(&profile)?;
    let mut value = serde_json::to_value(profile)?;
    value["protocol"] = json!("openvpn");
    let result = value.to_string();
    if result.len() > MAX_PROFILE {
        return Err(invalid("profile exceeds 1 MiB after packaging"));
    }
    Ok(result)
}

fn package(mut profile: Profile, directory: Option<&std::path::Path>) -> io::Result<Profile> {
    use base64::Engine;
    let mut options = Vec::new();
    for option in std::mem::take(&mut profile.options) {
        let key = option[0].as_str();
        if !FILES.contains(&key) {
            options.push(option);
            continue;
        }
        if !(2..=3).contains(&option.len()) || option.len() == 3 && key != "tls-auth" {
            return Err(invalid("invalid OpenVPN asset option"));
        }
        if option[1] == "[inline]" {
            if !profile.inline.contains_key(key) {
                return Err(invalid("OpenVPN inline asset is missing"));
            }
        } else {
            if profile.inline.contains_key(key) {
                return Err(invalid("duplicate OpenVPN asset"));
            }
            let directory = directory
                .ok_or_else(|| invalid("external OpenVPN assets require a profile file"))?;
            let data = asset(directory, &option[1])?;
            let data = if key == "pkcs12" {
                base64::engine::general_purpose::STANDARD.encode(data)
            } else {
                String::from_utf8(data).map_err(|_| invalid("OpenVPN PEM asset must be UTF-8"))?
            };
            profile.inline.insert(key.to_owned(), data);
        }
        if let Some(direction) = option.get(2) {
            options.push(vec!["key-direction".into(), direction.clone()]);
        }
    }
    profile.options = options;
    Ok(profile)
}

fn asset(directory: &std::path::Path, name: &str) -> io::Result<Vec<u8>> {
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Component;
    let components: Vec<_> = std::path::Path::new(name).components().collect();
    if components.is_empty()
        || components
            .iter()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(invalid(
            "OpenVPN assets must stay inside the profile directory",
        ));
    }
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.canonicalize()?)?;
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            unreachable!()
        };
        use std::os::unix::ffi::OsStrExt;
        let name = CString::new(component.as_bytes())
            .map_err(|_| invalid("invalid OpenVPN asset name"))?;
        let last = index + 1 == components.len();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if last { 0 } else { libc::O_DIRECTORY };
        // SAFETY: current is a live directory descriptor; name is NUL-terminated. The returned descriptor is owned below.
        let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(invalid("OpenVPN asset is missing, linked, or inaccessible"));
        }
        // SAFETY: openat returned a new owned descriptor.
        current = unsafe { File::from_raw_fd(fd) };
    }
    let metadata = current.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(invalid(
            "OpenVPN asset must be a regular file with one link",
        ));
    }
    let mut bytes = Vec::new();
    current
        .take(MAX_PROFILE as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PROFILE {
        return Err(invalid("OpenVPN asset exceeds 1 MiB"));
    }
    Ok(bytes)
}

fn source(input: &str) -> io::Result<Profile> {
    if input.contains('\0') || input.len() > MAX_PROFILE {
        return Err(invalid("invalid or oversized OpenVPN profile"));
    }
    let mut result = Profile {
        options: Vec::new(),
        inline: BTreeMap::new(),
    };
    let mut lines = input.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some(kind) = line.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
            if !FILES.contains(&kind) || result.inline.contains_key(kind) {
                return Err(invalid("unsupported or duplicate OpenVPN inline block"));
            }
            let end = format!("</{kind}>");
            let mut data = String::new();
            let mut closed = false;
            for line in lines.by_ref() {
                if line.trim() == end {
                    closed = true;
                    break;
                }
                if line.contains('\0') || line.trim_start().starts_with('<') {
                    return Err(invalid("invalid OpenVPN inline block"));
                }
                data.push_str(line);
                data.push('\n');
            }
            if !closed || data.trim().is_empty() {
                return Err(invalid("empty or unterminated OpenVPN inline block"));
            }
            result.inline.insert(kind.into(), data);
        } else {
            if result.options.len() >= 4096 || line.len() > 4096 {
                return Err(invalid("OpenVPN option limit exceeded"));
            }
            result.options.push(tokens(line)?);
        }
    }
    Ok(result)
}

fn tokens(line: &str) -> io::Result<Vec<String>> {
    let mut result = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut active = false;
    let mut escape = false;
    for c in line.chars() {
        if c.is_control() && c != '\t' {
            return Err(invalid("OpenVPN option contains controls"));
        }
        if escape {
            if !matches!(c, '\\' | '"' | '\'') {
                return Err(invalid("unsupported OpenVPN escape"));
            }
            token.push(c);
            escape = false;
            active = true;
        } else if c == '\\' {
            escape = true;
        } else if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                token.push(c);
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
            active = true;
        } else if c.is_whitespace() {
            if active {
                result.push(std::mem::take(&mut token));
                active = false;
            }
        } else if (c == '#' || c == ';') && !active {
            break;
        } else {
            token.push(c);
            active = true;
        }
    }
    if escape || quote.is_some() {
        return Err(invalid("unterminated OpenVPN quoting"));
    }
    if active {
        result.push(token);
    }
    if result.is_empty() || result.iter().any(|s| s.is_empty()) {
        return Err(invalid("empty OpenVPN option"));
    }
    Ok(result)
}

fn validate(profile: &Profile) -> io::Result<()> {
    if profile.options.len() > 4096 || profile.inline.keys().any(|k| !FILES.contains(&k.as_str())) {
        return Err(invalid("invalid OpenVPN profile structure"));
    }
    let mut seen = BTreeMap::<&str, usize>::new();
    for option in &profile.options {
        let Some(key) = option.first().map(String::as_str) else {
            return Err(invalid("empty OpenVPN option"));
        };
        if option
            .iter()
            .any(|s| s.is_empty() || s.len() > 4096 || s.chars().any(char::is_control))
        {
            return Err(invalid("invalid OpenVPN option value"));
        }
        let count = seen.entry(key).or_default();
        *count += 1;
        if *count > 1 && !matches!(key, "remote" | "route" | "route-ipv6") {
            return Err(invalid("duplicate OpenVPN option"));
        }
        let args = &option[1..];
        let valid = match key {
            "client" | "nobind" | "persist-key" | "persist-tun" | "remote-random"
            | "auth-nocache" | "float" | "fast-io" | "push-peer-info" => args.is_empty(),
            "dev" => args == ["tun"],
            "proto" => {
                args.len() == 1
                    && matches!(
                        args[0].as_str(),
                        "udp" | "udp4" | "udp6" | "tcp-client" | "tcp4-client" | "tcp6-client"
                    )
            }
            "remote" => {
                (1..=3).contains(&args.len())
                    && !args[0].starts_with('-')
                    && !args[0].chars().any(char::is_whitespace)
                    && args
                        .get(1)
                        .is_none_or(|p| p.parse::<u16>().is_ok_and(|p| p != 0))
                    && args.get(2).is_none_or(|p| {
                        matches!(
                            p.as_str(),
                            "udp"
                                | "udp4"
                                | "udp6"
                                | "tcp"
                                | "tcp4"
                                | "tcp6"
                                | "tcp-client"
                                | "tcp4-client"
                                | "tcp6-client"
                        )
                    })
                    && *count <= 16
            }
            "port" => args.len() == 1 && args[0].parse::<u16>().is_ok_and(|p| p != 0),
            "remote-cert-tls" => args == ["server"],
            "verify-x509-name" => {
                (1..=2).contains(&args.len())
                    && args
                        .get(1)
                        .is_none_or(|s| matches!(s.as_str(), "name" | "subject" | "name-prefix"))
            }
            "tls-version-min" | "tls-version-max" => {
                args.len() == 1 && matches!(args[0].as_str(), "1.2" | "1.3")
            }
            "topology" => args.len() == 1 && matches!(args[0].as_str(), "subnet" | "net30" | "p2p"),
            "cipher"
            | "data-ciphers"
            | "data-ciphers-fallback"
            | "auth"
            | "tls-cipher"
            | "tls-ciphersuites"
            | "remote-cert-eku" => args.len() == 1,
            "key-direction" => args == ["0"] || args == ["1"],
            "auth-user-pass" => args.is_empty(),
            "static-challenge" => args.len() == 2 && matches!(args[1].as_str(), "0" | "1"),
            "resolv-retry" => {
                args.len() == 1 && (args[0] == "infinite" || args[0].parse::<u32>().is_ok())
            }
            "explicit-exit-notify" => {
                args.len() <= 1 && args.first().is_none_or(|s| s.parse::<u32>().is_ok())
            }
            "tun-mtu"
            | "mssfix"
            | "sndbuf"
            | "rcvbuf"
            | "ping"
            | "ping-restart"
            | "connect-timeout"
            | "connect-retry-max"
            | "server-poll-timeout"
            | "reneg-sec"
            | "verb"
            | "mute" => args.len() == 1 && args[0].parse::<u32>().is_ok(),
            "keepalive" | "connect-retry" | "replay-window" => {
                (1..=2).contains(&args.len()) && args.iter().all(|s| s.parse::<u32>().is_ok())
            }
            "route" => {
                (1..=4).contains(&args.len())
                    && args[0].parse::<std::net::Ipv4Addr>().is_ok()
                    && args.iter().skip(1).all(|s| {
                        s.parse::<std::net::Ipv4Addr>().is_ok()
                            || s.parse::<u32>().is_ok()
                            || matches!(s.as_str(), "vpn_gateway" | "net_gateway")
                    })
            }
            "route-ipv6" => {
                (1..=3).contains(&args.len())
                    && args[0].split_once('/').is_some_and(|(ip, p)| {
                        ip.parse::<std::net::Ipv6Addr>().is_ok()
                            && p.parse::<u8>().is_ok_and(|p| p <= 128)
                    })
                    && args.iter().skip(1).all(|s| {
                        s.parse::<std::net::Ipv6Addr>().is_ok() || s.parse::<u32>().is_ok()
                    })
            }
            "redirect-gateway" => args.iter().all(|s| {
                matches!(
                    s.as_str(),
                    "def1"
                        | "local"
                        | "autolocal"
                        | "bypass-dhcp"
                        | "bypass-dns"
                        | "block-local"
                        | "ipv6"
                        | "!ipv4"
                )
            }),
            k if FILES.contains(&k) => {
                return Err(invalid(
                    "OpenVPN assets must be packaged inline; use a profile file for relative assets",
                ));
            }
            _ => return Err(invalid("unsupported OpenVPN option")),
        };
        if !valid {
            return Err(invalid(&format!("invalid OpenVPN option: {key}")));
        }
    }
    if !seen.contains_key("client")
        || !seen.contains_key("dev")
        || !seen.contains_key("remote")
        || !profile.inline.contains_key("ca")
    {
        return Err(invalid(
            "OpenVPN client requires dev tun, remote, and inline CA",
        ));
    }
    if profile.inline.contains_key("cert") != profile.inline.contains_key("key") {
        return Err(invalid(
            "OpenVPN certificate and key must be supplied together",
        ));
    }
    if profile.inline.values().any(|s| {
        s.trim().is_empty()
            || s.contains('\0')
            || s.lines().any(|line| line.trim_start().starts_with('<'))
    }) {
        return Err(invalid("invalid OpenVPN inline data"));
    }
    Ok(())
}
