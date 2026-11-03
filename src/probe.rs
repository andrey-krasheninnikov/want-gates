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

fn http(probe: &HttpProbe, proxy: &Proxy) -> io::Result<()> {
    let socks = ureq::Proxy::new(&format!(
        "socks5://{}:{}@127.0.0.1:{}",
        proxy.user, proxy.password, proxy.port
    ))
    .map_err(|_| invalid("invalid local probe proxy"))?;
    let client: ureq::Agent = ureq::Agent::config_builder()
        .proxy(Some(socks))
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(5)))
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
fn receive(stream: &mut TcpStream, buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
    stream.set_read_timeout(Some(remaining(deadline)?))?;
    stream.read_exact(buffer)
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
fn dns(probe: &DnsProbe, proxy: &Proxy) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = probe.address()?;
    let udp = UdpSocket::bind("127.0.0.1:0")?;
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
    let mut associate = vec![5, 3, 0, 1, 127, 0, 0, 1];
    associate.extend(udp.local_addr()?.port().to_be_bytes());
    send(&mut stream, &associate, deadline)?;
    let mut head = [0; 4];
    receive(&mut stream, &mut head, deadline)?;
    if head[..3] != [5, 0, 0] {
        return Err(invalid("SOCKS UDP association failed"));
    }
    let length = match head[3] {
        1 => 6,
        4 => 18,
        _ => return Err(invalid("SOCKS relay must use a literal loopback IP")),
    };
    let mut relay = vec![head[3]];
    relay.resize(length + 1, 0);
    receive(&mut stream, &mut relay[1..], deadline)?;
    let (relay, _) = address(&relay)?;
    if !relay.ip().is_loopback() || relay.port() == 0 {
        return Err(invalid("SOCKS relay is not local"));
    }
    udp.connect(relay)?;
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
    let mut packet = vec![0, 0, 0];
    match server.ip() {
        IpAddr::V4(ip) => {
            packet.push(1);
            packet.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.push(4);
            packet.extend(ip.octets());
        }
    }
    packet.extend(server.port().to_be_bytes());
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
    let answer = &buffer[3 + offset..n];
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
        let group_proxy = proxy.for_group(&group.id);
        let email = proxy.group_users.get(&group.id).map(String::as_str);
        let mut results = std::collections::BTreeMap::new();
        for capability in CAPABILITIES {
            client.check()?;
            let reason = if group.primary.is_none() {
                "primary_missing".to_owned()
            } else if only_verified.is_some_and(|m| {
                m.get(&group.id)
                    .and_then(|c| c.get(capability))
                    .is_none_or(|r| r != "verified")
            }) {
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
                                )? != format!("wgates-out-{}", group.primary.as_ref().unwrap())
                                {
                                    return Err(invalid("runtime route does not select primary"));
                                }
                                http(p, &group_proxy)
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
                                )? != format!("wgates-out-{}", group.primary.as_ref().unwrap())
                                {
                                    return Err(invalid("runtime route does not select primary"));
                                }
                                dns(p, &group_proxy)
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
            if only_verified.is_some_and(|m| {
                m.get(&group.id)
                    .and_then(|c| c.get(capability))
                    .is_some_and(|r| r == "verified")
            }) && reason != "verified"
            {
                return Err(io::Error::other(
                    "running traffic verification failed; inspect routing state",
                ));
            }
            results.insert(capability.to_owned(), reason.to_owned());
        }
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
