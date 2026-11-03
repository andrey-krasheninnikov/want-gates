use crate::{
    invalid,
    panel::Client,
    policy::{DnsProbe, HttpProbe},
    routing::{CAPABILITIES, Matrix, PROBE_TAG, Proxy},
    store::{Config, random_id},
};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

fn http(probe: &HttpProbe, proxy: &Proxy, deadline: Instant) -> io::Result<()> {
    let socks = ureq::Proxy::new(&format!(
        "socks5://{}:{}@127.0.0.1:{}",
        proxy.user, proxy.password, proxy.port
    ))
    .map_err(|_| invalid("invalid local probe proxy"))?;
    let client: ureq::Agent = ureq::Agent::config_builder()
        .proxy(Some(socks))
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(remaining(deadline)?))
        .build()
        .into();
    let mut response = client
        .get(&probe.url)
        .call()
        .map_err(|_| io::Error::other("HTTP probe failed"))?;
    if response.status().as_u16() != probe.expected_status {
        return Err(io::Error::other("HTTP probe returned an unexpected status"));
    }
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| io::Error::other("HTTP probe response could not be read"))?;
    if bytes.len() > 64 * 1024 {
        return Err(invalid("HTTP probe body exceeds 64 KiB"));
    }
    Ok(())
}
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "probe timed out"))
}
fn receive(stream: &mut TcpStream, mut buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !buffer.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "probe connection closed",
                ));
            }
            Ok(n) => buffer = &mut buffer[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn send(stream: &mut TcpStream, buffer: &[u8], deadline: Instant) -> io::Result<()> {
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(buffer)
}
fn address(bytes: &[u8]) -> io::Result<(SocketAddr, usize)> {
    let (ip, end) = match bytes.first() {
        Some(1) if bytes.len() >= 7 => {
            (IpAddr::from(<[u8; 4]>::try_from(&bytes[1..5]).unwrap()), 5)
        }
        Some(4) if bytes.len() >= 19 => (
            IpAddr::from(<[u8; 16]>::try_from(&bytes[1..17]).unwrap()),
            17,
        ),
        _ => return Err(invalid("invalid SOCKS IP address")),
    };
    Ok((
        SocketAddr::new(ip, u16::from_be_bytes([bytes[end], bytes[end + 1]])),
        end + 2,
    ))
}
fn socks(proxy: &Proxy, deadline: Instant) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], proxy.port)),
        remaining(deadline)?,
    )?;
    send(&mut stream, &[5, 1, 2], deadline)?;
    let mut response = [0; 2];
    receive(&mut stream, &mut response, deadline)?;
    if response != [5, 2] {
        return Err(invalid("SOCKS password authentication is required"));
    }
    let mut auth = vec![1, proxy.user.len() as u8];
    auth.extend(proxy.user.as_bytes());
    auth.push(proxy.password.len() as u8);
    auth.extend(proxy.password.as_bytes());
    send(&mut stream, &auth, deadline)?;
    receive(&mut stream, &mut response, deadline)?;
    if response != [1, 0] {
        return Err(invalid("SOCKS authentication failed"));
    }
    Ok(stream)
}
fn dns_query(probe: &DnsProbe) -> io::Result<(Vec<u8>, u16)> {
    let id = random_id()?;
    let id = u16::from_str_radix(&id[..4], 16).unwrap();
    let mut query = vec![];
    query.extend(id.to_be_bytes());
    query.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in probe.query_name.trim_end_matches('.').split('.') {
        query.push(label.len() as u8);
        query.extend(label.as_bytes());
    }
    query.push(0);
    let query_type = if probe.query_type == "A" { 1_u16 } else { 28 };
    query.extend(query_type.to_be_bytes());
    query.extend([0, 1]);
    Ok((query, query_type))
}
fn socks_reply(stream: &mut TcpStream, deadline: Instant) -> io::Result<SocketAddr> {
    let mut head = [0; 4];
    receive(stream, &mut head, deadline)?;
    if head[..3] != [5, 0, 0] {
        return Err(invalid("SOCKS request failed"));
    }
    let length = match head[3] {
        1 => 6,
        4 => 18,
        _ => return Err(invalid("SOCKS reply requires a literal IP")),
    };
    let mut reply = vec![head[3]];
    reply.resize(length + 1, 0);
    receive(stream, &mut reply[1..], deadline)?;
    Ok(address(&reply)?.0)
}

fn dns(probe: &DnsProbe, proxy: &Proxy) -> io::Result<()> {
    dns_over(probe, proxy, "udp")
}
fn dns_over(probe: &DnsProbe, proxy: &Proxy, network: &str) -> io::Result<()> {
    dns_at(
        probe,
        proxy,
        network,
        Instant::now() + Duration::from_secs(5),
    )
    .and_then(|(a, q, t)| dns_answer(&a, &q, t))
}
fn dns_at(
    probe: &DnsProbe,
    proxy: &Proxy,
    network: &str,
    deadline: Instant,
) -> io::Result<(Vec<u8>, Vec<u8>, u16)> {
    let server = probe.address()?;
    let (query, query_type) = dns_query(probe)?;
    let mut stream = socks(proxy, deadline)?;
    let mut destination = Vec::new();
    match server.ip() {
        IpAddr::V4(ip) => {
            destination.push(1);
            destination.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            destination.push(4);
            destination.extend(ip.octets());
        }
    }
    destination.extend(server.port().to_be_bytes());
    let answer = if network == "tcp" {
        let mut connect = vec![5, 1, 0];
        connect.extend(&destination);
        send(&mut stream, &connect, deadline)?;
        socks_reply(&mut stream, deadline)?;
        send(&mut stream, &(query.len() as u16).to_be_bytes(), deadline)?;
        send(&mut stream, &query, deadline)?;
        let mut size = [0; 2];
        receive(&mut stream, &mut size, deadline)?;
        let size = u16::from_be_bytes(size) as usize;
        if size > 4096 {
            return Err(invalid("DNS probe response exceeds 4096 bytes"));
        }
        let mut answer = vec![0; size];
        receive(&mut stream, &mut answer, deadline)?;
        answer
    } else {
        let udp = UdpSocket::bind("127.0.0.1:0")?;
        let mut associate = vec![5, 3, 0, 1, 127, 0, 0, 1];
        associate.extend(udp.local_addr()?.port().to_be_bytes());
        send(&mut stream, &associate, deadline)?;
        let relay = socks_reply(&mut stream, deadline)?;
        if !relay.ip().is_loopback() || relay.port() == 0 {
            return Err(invalid("SOCKS relay is not local"));
        }
        udp.connect(relay)?;
        let mut packet = vec![0, 0, 0];
        packet.extend(destination);
        packet.extend(&query);
        udp.set_write_timeout(Some(remaining(deadline)?))?;
        udp.send(&packet)?;
        let mut buffer = [0; 4096 + 22];
        udp.set_read_timeout(Some(remaining(deadline)?))?;
        let n = udp
            .recv(&mut buffer)
            .map_err(|_| io::Error::other("UDP DNS reply timed out or failed"))?;
        if n < 4 || buffer[..3] != [0, 0, 0] {
            return Err(invalid("invalid SOCKS UDP response"));
        }
        let (source, offset) = address(&buffer[3..n])?;
        if source != server {
            return Err(invalid("unexpected DNS response source"));
        }
        buffer[3 + offset..n].to_vec()
    };
    dns_header(&answer, &query)?;
    Ok((answer, query, query_type))
}
fn dns_header(answer: &[u8], query: &[u8]) -> io::Result<()> {
    // shortcut: require an uncompressed echoed question; extend for resolvers that compress it.
    if answer.len() < query.len()
        || answer[..2] != query[..2]
        || answer[2] & 0xfa != 0x80
        || answer[3] & 0x0f != 0
        || answer[4..6] != [0, 1]
        || answer[6..8] == [0, 0]
        || answer[12..query.len()] != query[12..]
    {
        return Err(invalid("DNS probe received no valid successful answer"));
    }
    Ok(())
}
fn dns_answer(answer: &[u8], query: &[u8], query_type: u16) -> io::Result<()> {
    dns_header(answer, query)?;
    let count = u16::from_be_bytes([answer[6], answer[7]]);
    let mut position = query.len();
    for _ in 0..count {
        loop {
            let b = *answer
                .get(position)
                .ok_or_else(|| invalid("truncated DNS answer"))?;
            if b & 0xc0 == 0xc0 {
                let low = *answer
                    .get(position + 1)
                    .ok_or_else(|| invalid("truncated DNS pointer"))?;
                if (((b as usize & 0x3f) << 8) | low as usize) >= answer.len() {
                    return Err(invalid("invalid DNS pointer"));
                }
                position += 2;
                break;
            }
            if b & 0xc0 != 0 {
                return Err(invalid("invalid DNS label"));
            }
            position += 1;
            if b == 0 {
                break;
            }
            position += b as usize;
        }
        let record = answer
            .get(position..position + 10)
            .ok_or_else(|| invalid("truncated DNS record"))?;
        let size = u16::from_be_bytes([record[8], record[9]]) as usize;
        let end = position + 10 + size;
        if end > answer.len() {
            return Err(invalid("truncated DNS record data"));
        }
        if record[..2] == query_type.to_be_bytes()
            && record[2..4] == [0, 1]
            && size == if query_type == 1 { 4 } else { 16 }
        {
            return Ok(());
        }
        position = end;
    }
    Err(invalid("DNS answer has no record of the requested type"))
}

pub fn transport(
    client: &Client,
    connection: &crate::store::Connection,
    group: &crate::store::Group,
    proxy: &Proxy,
    only_verified: Option<&std::collections::BTreeMap<String, String>>,
) -> io::Result<std::collections::BTreeMap<String, String>> {
    transport_at(client, connection, group, proxy, only_verified, None)
}
fn transport_at(
    client: &Client,
    connection: &crate::store::Connection,
    group: &crate::store::Group,
    proxy: &Proxy,
    only_verified: Option<&std::collections::BTreeMap<String, String>>,
    deadline: Option<Instant>,
) -> io::Result<std::collections::BTreeMap<String, String>> {
    let group_proxy = proxy.for_connection(&connection.id, &group.id);
    let email = proxy
        .connection_users
        .get(&connection.id)
        .or_else(|| proxy.group_users.get(&group.id))
        .map(String::as_str);
    let mut results = std::collections::BTreeMap::new();
    for capability in CAPABILITIES {
        client.check()?;
        let reason = if !crate::capability::permits(&connection.allowed_capabilities, capability) {
            "configured_limit".to_owned()
        } else if only_verified.is_some_and(|m| m.get(capability).is_none_or(|r| r != "verified")) {
            "not_rechecked".to_owned()
        } else {
            let result: Option<io::Result<()>> = match capability {
                "tcp_ipv4" | "tcp_ipv6" => {
                    let probe = if capability == "tcp_ipv4" {
                        &group.probes.tcp_ipv4
                    } else {
                        &group.probes.tcp_ipv6
                    };
                    probe.as_ref().map(|p| {
                        (|| {
                            let ip = p.address()?;
                            let port = url::Url::parse(&p.url)
                                .map_err(|_| invalid("invalid HTTP probe"))?
                                .port_or_known_default()
                                .unwrap();
                            if client.route_context(
                                PROBE_TAG,
                                &ip.to_string(),
                                None,
                                email,
                                "tcp",
                                port,
                            )? != format!("wgates-out-{}", &connection.id)
                            {
                                return Err(invalid("runtime route does not select primary"));
                            }
                            http(
                                p,
                                &group_proxy,
                                deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(5)),
                            )
                        })()
                    })
                }
                _ => {
                    let probe = if capability == "udp_ipv4" {
                        &group.probes.udp_ipv4
                    } else {
                        &group.probes.udp_ipv6
                    };
                    probe.as_ref().map(|p| {
                        (|| {
                            let address = p.address()?;
                            if client.route_context(
                                PROBE_TAG,
                                &address.ip().to_string(),
                                None,
                                email,
                                "udp",
                                address.port(),
                            )? != format!("wgates-out-{}", &connection.id)
                            {
                                return Err(invalid("runtime route does not select primary"));
                            }
                            dns_at(
                                p,
                                &group_proxy,
                                "udp",
                                deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(5)),
                            )
                            .and_then(|(a, q, t)| dns_answer(&a, &q, t))
                        })()
                    })
                }
            };
            match result {
                None => "probe_missing".to_owned(),
                Some(Ok(())) => "verified".to_owned(),
                Some(Err(error)) => format!("probe_failed: {error}"),
            }
        };
        if only_verified.is_some_and(|m| m.get(capability).is_some_and(|r| r == "verified"))
            && reason != "verified"
        {
            return Err(io::Error::other(
                "running traffic verification failed; inspect routing state",
            ));
        }
        results.insert(capability.to_owned(), reason.to_owned());
    }
    Ok(results)
}
pub fn check(
    client: &Client,
    config: &Config,
    proxy: &Proxy,
    only_verified: Option<&Matrix>,
) -> io::Result<Matrix> {
    let mut matrix = Matrix::new();
    for group in config
        .groups
        .iter()
        .filter(|g| config.rules.iter().any(|r| r.group_id == g.id))
    {
        let results = if let Some(connection) = crate::domain::connection(config, group) {
            transport(
                client,
                connection,
                group,
                proxy,
                only_verified.and_then(|m| m.get(&group.id)),
            )?
        } else {
            CAPABILITIES
                .iter()
                .map(|c| (c.to_string(), "primary_missing".to_owned()))
                .collect()
        };
        matrix.insert(group.id.clone(), results);
    }
    for group in config.groups.iter().filter(|g| {
        crate::domain::rules(config)
            .iter()
            .any(|(_, r)| r.group_id == g.id)
    }) {
        let connection = crate::domain::connection(config, group);
        let reason = match (
            connection,
            connection.and_then(|c| c.dns.as_ref()),
            group.probes.dns.as_ref(),
        ) {
            (None, _, _) => "primary_missing".to_owned(),
            (_, None, _) => "dns_missing".to_owned(),
            (_, _, None) => "probe_missing".to_owned(),
            (_, Some(server), Some(probe)) => {
                if only_verified.is_some_and(|m| {
                    m.get(&group.id)
                        .and_then(|r| r.get("dns"))
                        .is_none_or(|r| r != "verified")
                }) {
                    "not_rechecked".to_owned()
                } else {
                    let resolver = crate::policy::Resolver::parse(server)?;
                    if matrix[&group.id]
                        .get(&resolver.capability())
                        .is_some_and(|v| v == "configured_limit")
                    {
                        "configured_limit".to_owned()
                    } else if matrix[&group.id]
                        .get(&resolver.capability())
                        .is_none_or(|v| v != "verified")
                    {
                        "dns_transport_unverified".to_owned()
                    } else {
                        let result = (|| {
                            client.check()?;
                            if client.route(PROBE_TAG, "127.0.0.1", "udp", 53)? != "wgates-dns" {
                                return Err(invalid("DNS interception route is missing"));
                            }
                            dns(
                                &DnsProbe {
                                    server: "127.0.0.1:53".into(),
                                    query_name: crate::policy::domain_name(&probe.query_name)?,
                                    query_type: probe.query_type.clone(),
                                },
                                proxy,
                            )
                        })();
                        match result {
                            Ok(()) => "verified".to_owned(),
                            Err(e) => format!("probe_failed: {e}"),
                        }
                    }
                }
            }
        };
        if only_verified.is_some_and(|m| {
            m.get(&group.id)
                .and_then(|r| r.get("dns"))
                .is_some_and(|r| r == "verified")
        }) && reason != "verified"
        {
            return Err(io::Error::other(
                "running DNS verification failed; inspect routing state",
            ));
        }
        matrix
            .get_mut(&group.id)
            .unwrap()
            .insert("dns".into(), reason);
    }
    Ok(matrix)
}

pub fn connection(
    client: &Client,
    config: &Config,
    connection: &crate::store::Connection,
    proxy: &Proxy,
) -> io::Result<std::collections::BTreeMap<String, String>> {
    connection_at(client, config, connection, proxy, None)
}
fn connection_at(
    client: &Client,
    config: &Config,
    connection: &crate::store::Connection,
    proxy: &Proxy,
    deadline: Option<Instant>,
) -> io::Result<std::collections::BTreeMap<String, String>> {
    let group = config
        .groups
        .iter()
        .find(|g| g.id == connection.group_id)
        .ok_or_else(|| invalid("connection group missing"))?;
    let mut results = transport_at(client, connection, group, proxy, None, deadline)?;
    let reason = match (&connection.dns, &group.probes.dns) {
        (None, _) => "dns_missing".to_owned(),
        (_, None) => "probe_missing".to_owned(),
        (Some(server), Some(probe)) => {
            let resolver = crate::policy::Resolver::parse(server)?;
            if !crate::capability::permits(&connection.allowed_capabilities, &resolver.capability())
            {
                "configured_limit".to_owned()
            } else if results
                .get(&resolver.capability())
                .is_none_or(|v| v != "verified")
            {
                "dns_transport_unverified".to_owned()
            } else {
                client.check()?;
                let result = (|| {
                    if client.route_context(
                        PROBE_TAG,
                        &resolver.address.ip().to_string(),
                        None,
                        proxy
                            .connection_users
                            .get(&connection.id)
                            .map(String::as_str),
                        resolver.network,
                        resolver.address.port(),
                    )? != format!("wgates-out-{}", connection.id)
                    {
                        return Err(invalid("DNS diagnostic route does not select connection"));
                    }
                    dns_at(
                        &DnsProbe {
                            server: resolver.address.to_string(),
                            query_name: crate::policy::domain_name(&probe.query_name)?,
                            query_type: probe.query_type.clone(),
                        },
                        &proxy.for_connection(&connection.id, &group.id),
                        resolver.network,
                        deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(5)),
                    )
                    .and_then(|(a, q, t)| dns_answer(&a, &q, t))
                })();
                match result {
                    Ok(()) => "verified".into(),
                    Err(e) => format!("probe_failed: {e}"),
                }
            }
        }
    };
    results.insert("dns".into(), reason);
    Ok(results)
}

fn dns_name(bytes: &[u8], position: &mut usize) -> io::Result<String> {
    let mut offset = *position;
    let mut jumped = false;
    let mut labels = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    loop {
        if !seen.insert(offset) || seen.len() > 128 {
            return Err(invalid("cyclic DNS name"));
        }
        let size = *bytes
            .get(offset)
            .ok_or_else(|| invalid("truncated DNS name"))?;
        if size & 0xc0 == 0xc0 {
            let low = *bytes
                .get(offset + 1)
                .ok_or_else(|| invalid("truncated DNS pointer"))?;
            if !jumped {
                *position = offset + 2;
                jumped = true;
            }
            offset = ((size as usize & 0x3f) << 8) | low as usize;
            continue;
        }
        if size & 0xc0 != 0 {
            return Err(invalid("invalid DNS label"));
        }
        offset += 1;
        if size == 0 {
            if !jumped {
                *position = offset;
            }
            break;
        }
        let label = bytes
            .get(offset..offset + size as usize)
            .ok_or_else(|| invalid("truncated DNS label"))?;
        labels.push(
            std::str::from_utf8(label)
                .map_err(|_| invalid("invalid DNS name"))?
                .to_ascii_lowercase(),
        );
        offset += size as usize;
        if labels.len() > 127 {
            return Err(invalid("DNS name exceeds limit"));
        }
    }
    crate::policy::domain_name(&labels.join("."))
}
fn lookup(
    name: &str,
    kind: &str,
    resolver: &crate::policy::Resolver,
    proxy: &Proxy,
    deadline: Instant,
) -> io::Result<Vec<IpAddr>> {
    let mut name = crate::policy::domain_name(name)?;
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..8 {
        if !seen.insert(name.clone()) {
            return Err(invalid("cyclic DNS alias"));
        }
        let (answer, query, typ) = dns_at(
            &DnsProbe {
                server: resolver.address.to_string(),
                query_name: name.clone(),
                query_type: kind.into(),
            },
            proxy,
            resolver.network,
            deadline,
        )?;
        let mut offset = query.len();
        let mut aliases = std::collections::BTreeMap::new();
        let mut records = Vec::new();
        for _ in 0..u16::from_be_bytes([answer[6], answer[7]]) {
            let owner = dns_name(&answer, &mut offset)?;
            let header = answer
                .get(offset..offset + 10)
                .ok_or_else(|| invalid("truncated DNS record"))?;
            let record_type = u16::from_be_bytes([header[0], header[1]]);
            let size = u16::from_be_bytes([header[8], header[9]]) as usize;
            offset += 10;
            let data = answer
                .get(offset..offset + size)
                .ok_or_else(|| invalid("truncated DNS record"))?;
            if header[2..4] == [0, 1] {
                if record_type == 5 {
                    let mut p = offset;
                    let canonical = dns_name(&answer, &mut p)?;
                    if p != offset + size {
                        return Err(invalid("invalid CNAME data"));
                    }
                    aliases.insert(owner, canonical);
                } else if record_type == typ {
                    let ip = match (typ, size) {
                        (1, 4) => Some(IpAddr::from(<[u8; 4]>::try_from(data).unwrap())),
                        (28, 16) => Some(IpAddr::from(<[u8; 16]>::try_from(data).unwrap())),
                        _ => None,
                    };
                    if let Some(ip) = ip {
                        records.push((owner, ip));
                    }
                }
            }
            offset += size;
        }
        let mut canonical = name.clone();
        let mut chain = std::collections::BTreeSet::new();
        while let Some(next) = aliases.get(&canonical) {
            if !chain.insert(canonical.clone()) || chain.len() > 8 {
                return Err(invalid("cyclic DNS alias"));
            }
            canonical = next.clone();
        }
        let ips: Vec<_> = records
            .into_iter()
            .filter(|(owner, ip)| {
                owner == &canonical
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !matches!(ip,IpAddr::V6(a) if a.to_ipv4_mapped().is_some())
            })
            .map(|(_, ip)| ip)
            .take(16)
            .collect();
        if !ips.is_empty() {
            return Ok(ips);
        }
        if canonical == name {
            return Err(invalid("DNS returned no address for target"));
        }
        name = canonical;
    }
    Err(invalid("DNS alias limit exceeded"))
}
#[derive(Debug, Clone)]
struct PinnedResolver {
    host: String,
    addresses: Vec<SocketAddr>,
}
impl ureq::unversioned::resolver::Resolver for PinnedResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        _: &ureq::config::Config,
        _: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let host = uri
            .host()
            .ok_or(ureq::Error::HostNotFound)?
            .trim_matches(['[', ']']);
        let port = uri
            .port_u16()
            .or_else(|| match uri.scheme_str() {
                Some("http") => Some(80),
                Some("https") => Some(443),
                _ => None,
            })
            .ok_or(ureq::Error::HostNotFound)?;
        let mut addresses = self.empty();
        if let Ok(ip) = host.parse::<IpAddr>() {
            addresses.push(SocketAddr::new(ip, port));
        } else if host.eq_ignore_ascii_case(&self.host) {
            for address in &self.addresses {
                addresses.push(*address);
            }
        }
        if addresses.is_empty() {
            Err(ureq::Error::HostNotFound)
        } else {
            Ok(addresses)
        }
    }
}
fn tls_cause(error: &ureq::Error) -> Option<&rustls::Error> {
    match error {
        ureq::Error::Rustls(error) => Some(error),
        ureq::Error::Io(error) => error
            .get_ref()
            .and_then(|source| source.downcast_ref::<rustls::Error>()),
        _ => None,
    }
}
fn target_http(
    check: &crate::health::Healthcheck,
    proxy: &Proxy,
    addresses: &[SocketAddr],
    deadline: Instant,
) -> io::Result<()> {
    let url = url::Url::parse(&check.target).map_err(|_| invalid("invalid target"))?;
    let pinned = PinnedResolver {
        host: url.host_str().unwrap().into(),
        addresses: addresses.to_vec(),
    };
    let mut extra_roots = check.ca_pem.is_some();
    loop {
        let mut config = ureq::Agent::config_builder()
            .proxy(Some(
                ureq::Proxy::new(&format!(
                    "socks5://{}:{}@127.0.0.1:{}",
                    proxy.user, proxy.password, proxy.port
                ))
                .map_err(|_| invalid("invalid probe proxy"))?,
            ))
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(remaining(deadline)?));
        if extra_roots {
            config = config.tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(crate::health::certificates(check.ca_pem.as_ref().unwrap())?.into())
                    .build(),
            );
        }
        let client = ureq::Agent::with_parts(
            config.build(),
            ureq::unversioned::transport::DefaultConnector::default(),
            pinned.clone(),
        );
        let response = client.get(&check.target).call();
        let mut response = match response {
            Err(ref error)
                if extra_roots
                    && matches!(
                        tls_cause(error),
                        Some(rustls::Error::InvalidCertificate(
                            rustls::CertificateError::UnknownIssuer
                        ))
                    ) =>
            {
                extra_roots = false;
                continue;
            }
            Err(ref error)
                if matches!(error, ureq::Error::Tls(_)) || tls_cause(error).is_some() =>
            {
                return Err(io::Error::other("tls_failed"));
            }
            Err(ureq::Error::Timeout(_)) => return Err(io::Error::other("probe_timed_out")),
            Err(_) => return Err(io::Error::other("target_failed")),
            Ok(response) => response,
        };
        if response.status().as_u16() != check.expected_status.unwrap_or(200) {
            return Err(io::Error::other("target_status_failed"));
        }
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| io::Error::other("target_failed"))?;
        if bytes.len() > 64 * 1024 {
            return Err(invalid("target_response_too_large"));
        }
        return Ok(());
    }
}
pub fn health(
    client: &Client,
    config: &Config,
    connection: &crate::store::Connection,
    proxy: &Proxy,
) -> io::Result<std::collections::BTreeMap<String, String>> {
    let group = config
        .groups
        .iter()
        .find(|g| g.id == connection.group_id)
        .ok_or_else(|| invalid("group missing"))?;
    let check = group
        .healthcheck
        .as_ref()
        .ok_or_else(|| invalid("healthcheck missing"))?;
    let deadline = Instant::now() + Duration::from_secs(check.timeout_seconds);
    match health_at(client, config, connection, proxy, deadline) {
        Err(error) if error.kind() == io::ErrorKind::TimedOut => Ok(
            std::collections::BTreeMap::from([("health".into(), "probe_timed_out".into())]),
        ),
        result => result,
    }
}
fn health_at(
    client: &Client,
    config: &Config,
    connection: &crate::store::Connection,
    proxy: &Proxy,
    deadline: Instant,
) -> io::Result<std::collections::BTreeMap<String, String>> {
    let group = config
        .groups
        .iter()
        .find(|g| g.id == connection.group_id)
        .ok_or_else(|| invalid("group missing"))?;
    let check = group
        .healthcheck
        .as_ref()
        .ok_or_else(|| invalid("healthcheck missing"))?;
    let bounded = client.until(deadline);
    let client = &bounded;
    let user = proxy
        .connection_users
        .get(&connection.id)
        .ok_or_else(|| invalid("connection requires prepared diagnostic routes"))?;
    let local = proxy.for_connection(&connection.id, &group.id);
    let url = url::Url::parse(&check.target).map_err(|_| invalid("invalid target"))?;
    let port = url.port_or_known_default().unwrap();
    let host = url.host_str().unwrap().trim_matches(['[', ']']);
    let mut results = std::collections::BTreeMap::new();
    let literal = host.parse::<IpAddr>().ok();
    let resolver = if literal.is_none() {
        let Some(server) = &connection.dns else {
            results.insert("health".into(), "dns_missing".into());
            return Ok(results);
        };
        let resolver = crate::policy::Resolver::parse(server)?;
        if !crate::capability::permits(&connection.allowed_capabilities, &resolver.capability()) {
            results.insert("health".into(), "dns_capability_missing".into());
            return Ok(results);
        }
        if client.route_context(
            PROBE_TAG,
            &resolver.address.ip().to_string(),
            None,
            Some(user),
            resolver.network,
            resolver.address.port(),
        )? != format!("wgates-out-{}", connection.id)
        {
            return Err(invalid("healthcheck DNS route changed"));
        }
        Some(resolver)
    } else {
        None
    };
    let mut target_error = if literal.is_some()
        || !["tcp_ipv4", "tcp_ipv6"]
            .into_iter()
            .any(|c| crate::capability::permits(&connection.allowed_capabilities, c))
    {
        "capability_missing".to_owned()
    } else {
        "dns_failed".to_owned()
    };
    let mut target_ok = false;
    for (kind, capability) in [("A", "tcp_ipv4"), ("AAAA", "tcp_ipv6")] {
        if Instant::now() >= deadline
            || !crate::capability::permits(&connection.allowed_capabilities, capability)
        {
            continue;
        }
        let ips = if let Some(ip) = literal {
            if ip.is_ipv4() != (kind == "A") {
                continue;
            }
            vec![ip]
        } else {
            lookup(host, kind, resolver.as_ref().unwrap(), &local, deadline).unwrap_or_default()
        };
        let addresses = ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            continue;
        }
        for address in &addresses {
            client.check()?;
            if client.route_context(
                PROBE_TAG,
                &address.ip().to_string(),
                None,
                proxy
                    .connection_users
                    .get(&connection.id)
                    .map(String::as_str),
                "tcp",
                port,
            )? != format!("wgates-out-{}", connection.id)
            {
                return Err(invalid("healthcheck diagnostic route changed"));
            }
        }
        let target = if url.scheme() == "tcp" {
            let mut result = Err(io::Error::other("target_failed"));
            for address in &addresses {
                result = (|| {
                    let mut stream = socks(&local, deadline)?;
                    let mut request = vec![5, 1, 0];
                    match address.ip() {
                        IpAddr::V4(ip) => {
                            request.push(1);
                            request.extend(ip.octets());
                        }
                        IpAddr::V6(ip) => {
                            request.push(4);
                            request.extend(ip.octets());
                        }
                    }
                    request.extend(port.to_be_bytes());
                    send(&mut stream, &request, deadline)?;
                    socks_reply(&mut stream, deadline)?;
                    let (message, expected) = check.tcp_exchange()?;
                    send(&mut stream, &message, deadline)?;
                    let mut answer = vec![0; expected.len()];
                    receive(&mut stream, &mut answer, deadline)?;
                    if answer != expected {
                        return Err(invalid("target_response_mismatch"));
                    }
                    Ok(())
                })();
                if result.is_ok() {
                    break;
                }
            }
            result.map_err(|_| io::Error::other("target_failed"))
        } else {
            let mut result = Err(io::Error::other("target_failed"));
            for address in &addresses {
                result = target_http(check, &local, std::slice::from_ref(address), deadline);
                if result.is_ok() {
                    break;
                }
            }
            result
        };
        match target {
            Ok(()) => {
                target_ok = true;
                break;
            }
            Err(error) => target_error = error.to_string(),
        }
    }
    if !target_ok {
        results.insert("health".into(), target_error);
        return Ok(results);
    }
    let mut scoped = config.clone();
    let g = scoped.groups.iter_mut().find(|g| g.id == group.id).unwrap();
    let mut required = check.required_capabilities.clone();
    if let Some(server) = &connection.dns {
        required.push(crate::policy::Resolver::parse(server)?.capability());
    }
    if !required.iter().any(|c| c == "tcp_ipv4") {
        g.probes.tcp_ipv4 = None;
    }
    if !required.iter().any(|c| c == "tcp_ipv6") {
        g.probes.tcp_ipv6 = None;
    }
    if !required.iter().any(|c| c == "udp_ipv4") {
        g.probes.udp_ipv4 = None;
    }
    if !required.iter().any(|c| c == "udp_ipv6") {
        g.probes.udp_ipv6 = None;
    }
    match connection_at(client, &scoped, connection, proxy, Some(deadline)) {
        Ok(sample) => results.extend(sample),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => {
            results.insert("health".into(), "probe_timed_out".into());
            return Ok(results);
        }
        Err(error) => return Err(error),
    }
    let reason = if check
        .required_capabilities
        .iter()
        .any(|c| results.get(c).is_none_or(|r| r != "verified"))
    {
        "capability_missing"
    } else if crate::domain::rules(config)
        .iter()
        .any(|(_, r)| r.group_id == group.id)
        && results.get("dns").is_none_or(|v| v != "verified")
    {
        "dns_failed"
    } else {
        "verified"
    };
    results.insert("health".into(), reason.into());
    Ok(results)
}
