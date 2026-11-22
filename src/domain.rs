use crate::{
    invalid,
    panel::{Client, Snapshot},
    policy::{Domain, Network, Resolver, Rule, domain_name},
    routing::{Input, Matrix, PROBE_TAG, allowed},
    store::{Config, Connection, Group},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, SocketAddr},
};

pub fn rules(config: &Config) -> Vec<(Domain, &Rule)> {
    let mut rules: Vec<_> = config
        .rules
        .iter()
        .filter_map(|r| Domain::parse(&r.destination).ok().map(|d| (d, r)))
        .collect();
    rules.sort_by(|(a, ar), (b, br)| {
        b.specificity()
            .cmp(&a.specificity())
            .then(ar.destination.cmp(&br.destination))
    });
    rules
}
pub fn winner<'a>(config: &'a Config, name: &str) -> Option<&'a Rule> {
    rules(config)
        .into_iter()
        .find(|(d, _)| d.matches(name))
        .map(|(_, r)| r)
}
pub fn connection<'a>(config: &'a Config, group: &Group) -> Option<&'a Connection> {
    group
        .primary
        .as_ref()
        .and_then(|id| config.connections.iter().find(|c| &c.id == id))
}
pub fn usable(config: &Config, group: &Group, matrix: &Matrix) -> bool {
    connection(config, group)
        .and_then(|c| c.dns.as_ref())
        .and_then(|d| Resolver::parse(d).ok())
        .is_some_and(|r| {
            allowed(matrix, &group.id, "dns") && allowed(matrix, &group.id, &r.capability())
        })
}
pub fn describe(config: &Config) -> Vec<Value> {
    config.groups.iter().filter(|g|rules(config).iter().any(|(_,r)|r.group_id==g.id)).map(|g|json!({"group_id":g.id,"connection_id":g.primary,"server":connection(config,g).and_then(|c|c.dns.as_ref()),"probe":g.probes.dns,"records":["A","AAAA"],"fallback":"blocked","cache":"disabled"})).collect()
}
pub fn validate(input: &Input, base: &Snapshot) -> io::Result<()> {
    let domains = rules(&input.config);
    if domains.is_empty() {
        return Ok(());
    }
    let dns = &base.template["dns"];
    if !dns.is_null() && !dns.is_object() || dns.get("servers").is_some_and(|v| !v.is_array()) {
        return Err(invalid(
            "invalid panel DNS object or servers list; reconcile before preview",
        ));
    }
    if dns
        .get("script")
        .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
        || dns["useSystemHosts"] == true
        || dns.get("queryStrategy").is_some_and(|v| v != "UseIP")
        || base.template["routing"]
            .get("domainStrategy")
            .is_some_and(|v| v != "AsIs")
    {
        return Err(invalid(
            "domain DNS requires AsIs routing, UseIP DNS, no DNS script and no system hosts; reconcile the panel before preview",
        ));
    }
    let servers: Vec<_> = dns["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|v| !crate::routing::owned(v))
        .collect();
    // Xray uses the first server if neither domain matching nor fallback selects one.
    if dns["disableFallback"] == true
        || (!servers.is_empty() && servers.iter().all(|v| v["skipFallback"] == true))
    {
        return Err(invalid(
            "domain DNS requires panel DNS fallback; reconcile disableFallback and skipFallback before preview",
        ));
    }
    if let Some(hosts) = dns.get("hosts") {
        let hosts = hosts
            .as_object()
            .ok_or_else(|| invalid("invalid panel DNS hosts"))?;
        for key in hosts.keys() {
            let host = if let Some(name) = key.strip_prefix("domain:") {
                Domain::parse(name)
            } else {
                Domain::parse(&format!(
                    "full:{}",
                    key.strip_prefix("full:").unwrap_or(key)
                ))
            }
            .map_err(|_| {
                invalid("unbounded DNS hosts pattern; reconcile it before domain preview")
            })?;
            if domains
                .iter()
                .any(|(d, _)| d.matches(&host.name) || host.matches(&d.name))
            {
                return Err(invalid(
                    "panel DNS hosts overlap protected domains; reconcile before preview",
                ));
            }
        }
    }
    for group in &input.config.groups {
        if !domains.iter().any(|(_, r)| r.group_id == group.id) {
            continue;
        }
        if let Some(probe) = &group.probes.dns {
            let name = domain_name(&probe.query_name)?;
            if winner(&input.config, &name).is_none_or(|r| r.group_id != group.id) {
                return Err(invalid(
                    "DNS probe name must select its group under the most-specific domain rule",
                ));
            }
        }
    }
    for profile in input.profiles.values() {
        for address in [
            profile.pointer("/settings/address"),
            profile.pointer("/settings/vnext/0/address"),
        ]
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        {
            if let Ok(name) = domain_name(address)
                && winner(&input.config, &name).is_some()
            {
                return Err(invalid(
                    "VLESS server name overlaps a protected domain; avoid a DNS bootstrap cycle",
                ));
            }
        }
        if profile["protocol"] == "forti" {
            let forti = crate::forti::decoded_profile(profile)?;
            if let Some(host) = crate::forti::option(&forti, "host")
                && let Ok(name) = domain_name(host)
                && winner(&input.config, &name).is_some()
            {
                return Err(invalid(
                    "Forti server name overlaps a protected domain; avoid a DNS bootstrap cycle",
                ));
            }
        }
        if profile["protocol"] == "openvpn"
            && let Some(options) = profile["options"].as_array()
        {
            for option in options.iter().filter(|o| o[0] == "remote") {
                if let Some(address) = option[1].as_str()
                    && let Ok(name) = domain_name(address)
                    && winner(&input.config, &name).is_some()
                {
                    return Err(invalid(
                        "OpenVPN server name overlaps a protected domain; avoid a DNS bootstrap cycle",
                    ));
                }
            }
        }
    }
    Ok(())
}

pub fn render(
    input: &Input,
    template: &mut Value,
    ingress: &[String],
    matrix: &Matrix,
) -> io::Result<Vec<Value>> {
    let domains = rules(&input.config);
    let mut servers = template["dns"]["servers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    servers.retain(|v| !crate::routing::owned(v));
    if domains.is_empty() {
        if template["dns"]["servers"]
            .as_array()
            .is_some_and(|a| a.iter().any(crate::routing::owned))
        {
            template["dns"]["servers"] = json!(servers);
        }
        return Ok(Vec::new());
    }
    if servers.is_empty() {
        servers.push(json!({"address":"localhost","tag":"wgates-default-dns"}));
    }
    let mut owned_servers = Vec::new();
    let mut dns_policy = Vec::new();
    let mut routes = Vec::new();
    for group in &input.config.groups {
        if !domains.iter().any(|(_, r)| r.group_id == group.id) {
            continue;
        }
        let Some(connection) = connection(&input.config, group) else {
            continue;
        };
        let Some(server) = &connection.dns else {
            continue;
        };
        let resolver = Resolver::parse(server)?;
        let tag = format!("wgates-dns-{}", connection.id);
        // Always terminate this tag before any panel-generated direct DNS exception.
        routes.push(json!({"type":"field","ruleTag":format!("{tag}-route"),"inboundTag":[tag],"outboundTag":if usable(&input.config,group,matrix){format!("wgates-out-{}",connection.id)}else{"wgates-block".into()}}));
        for protocol in ["tcp", "udp"] {
            let v4 = allowed(matrix, &group.id, &format!("{protocol}_ipv4"));
            let v6 = allowed(matrix, &group.id, &format!("{protocol}_ipv6"));
            if usable(&input.config, group, matrix) && (v4 || v6) {
                let mut outbound = crate::routing::outbound(input, &connection.id, false);
                outbound["tag"] = json!(format!("wgates-domain-{}-{protocol}", connection.id));
                outbound["targetStrategy"] = json!(match (v4, v6) {
                    (true, true) => "ForceIP",
                    (true, false) => "ForceIPv4",
                    _ => "ForceIPv6",
                });
                template["outbounds"].as_array_mut().unwrap().push(outbound);
            }
        }
        for (domain, rule) in &domains {
            if rule.group_id != group.id {
                continue;
            }
            owned_servers.push((domain.specificity(),rule.destination.clone(),json!({"address":if resolver.network=="tcp"{format!("tcp://{}",resolver.address)}else{resolver.address.ip().to_string()},"port":resolver.address.port(),"domains":[domain.pattern()],"tag":tag,"finalQuery":true,"skipFallback":true,"disableCache":true,"serveStale":false,"timeoutMs":4000})));
        }
    }
    for (domain, rule) in &domains {
        let group = input
            .config
            .groups
            .iter()
            .find(|g| g.id == rule.group_id)
            .unwrap();
        let ready = usable(&input.config, group, matrix);
        if ready {
            dns_policy.push(json!({"domain":[domain.pattern()],"qType":"1,28","action":"hijack"}));
        }
        dns_policy.push(json!({"domain":[domain.pattern()],"action":"return","rCode":5}));
        for protocol in ["tcp", "udp"] {
            for (family, network) in [(4, "0.0.0.0/0"), (6, "::/0")] {
                let allow = ready && allowed(matrix, &group.id, &format!("{protocol}_ipv{family}"));
                routes.push(json!({"type":"field","ruleTag":format!("wgates-{}-{protocol}-ipv{family}",rule.id),"inboundTag":ingress,"domain":[domain.pattern()],"ip":[network],"network":protocol,"outboundTag":if allow{format!("wgates-out-{}",group.primary.as_ref().unwrap())}else{"wgates-block".into()}}));
            }
            let allow = ready
                && [4, 6]
                    .iter()
                    .any(|f| allowed(matrix, &group.id, &format!("{protocol}_ipv{f}")));
            routes.push(json!({"type":"field","ruleTag":format!("wgates-{}-{protocol}",rule.id),"inboundTag":ingress,"domain":[domain.pattern()],"network":protocol,"outboundTag":if allow{format!("wgates-domain-{}-{protocol}",group.primary.as_ref().unwrap())}else{"wgates-block".into()}}));
        }
        routes.push(json!({"type":"field","ruleTag":format!("wgates-{}-block",rule.id),"inboundTag":ingress,"domain":[domain.pattern()],"outboundTag":"wgates-block"}));
    }
    // Protected non-address queries have already returned REFUSED above.
    dns_policy.push(json!({"qType":"1,28","action":"hijack"}));
    dns_policy.push(json!({"action":"return","rCode":5}));
    template["outbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"tag":"wgates-dns","protocol":"dns","settings":{"rules":dns_policy}}));
    routes.insert(0,json!({"type":"field","ruleTag":"wgates-dns-intercept","inboundTag":ingress,"network":"tcp,udp","port":"53","outboundTag":"wgates-dns"}));
    owned_servers.sort_by(|(a, an, _), (b, bn, _)| b.cmp(a).then(an.cmp(bn)));
    let mut merged: Vec<_> = owned_servers.into_iter().map(|(_, _, v)| v).collect();
    merged.extend(servers);
    if template.get("dns").is_none() {
        template["dns"] = json!({});
    }
    template["dns"]["servers"] = json!(merged);
    Ok(routes)
}

fn panel_private(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    let ip = match ip {
        IpAddr::V6(a) if a.to_ipv4_mapped().is_some() => IpAddr::V4(a.to_ipv4_mapped().unwrap()),
        a => a,
    };
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    let basic = match ip {
        IpAddr::V4(a) => a.is_private() || a.is_link_local() || a.octets()[..3] == [224, 0, 0],
        IpAddr::V6(a) => {
            a.is_unique_local() || a.is_unicast_link_local() || (a.segments()[0] & 0xff0f == 0xff02)
        }
    };
    if basic {
        return true;
    }
    for prefix in [
        "100.64.0.0/10",
        "2002::/16",
        "2001::/32",
        "64:ff9b:1::/48",
        "fec0::/10",
    ] {
        if Network::parse(prefix).unwrap().contains(ip) {
            return true;
        }
    }
    if let IpAddr::V6(a) = ip
        && Network::parse("64:ff9b::/96").unwrap().contains(ip)
    {
        let b = a.octets();
        return panel_private(IpAddr::V4([b[12], b[13], b[14], b[15]].into()));
    }
    false
}
fn endpoint(entry: &Value) -> Option<SocketAddr> {
    let value = entry.as_str().or_else(|| entry["address"].as_str())?.trim();
    let value = value
        .split_once("://")
        .map_or(value, |(_, v)| v)
        .split('/')
        .next()?;
    let mut address = value.parse::<SocketAddr>().ok().or_else(|| {
        value
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .ok()
            .map(|a| SocketAddr::new(a, 53))
    })?;
    if let Some(port) = entry["port"].as_u64().filter(|p| *p > 0) {
        address.set_port(u16::try_from(port).ok()?);
    }
    Some(address)
}
// 3x-ui 3.8.5 normalizes this panel-owned rule on every template save.
pub fn normalise_panel_dns(template: &mut Value) -> io::Result<()> {
    let mut groups: BTreeMap<u16, Vec<String>> = BTreeMap::new();
    for server in template["dns"]["servers"].as_array().into_iter().flatten() {
        if let Some(a) = endpoint(server)
            && panel_private(a.ip())
        {
            groups
                .entry(a.port())
                .or_default()
                .push(a.ip().to_canonical().to_string());
        }
    }
    for ips in groups.values_mut() {
        ips.sort();
        ips.dedup();
    }
    let Some(rules) = template["routing"]["rules"].as_array_mut() else {
        return Ok(());
    };
    fn ips(value: &Value) -> Vec<String> {
        if let Some(s) = value.as_str() {
            vec![s.to_owned()]
        } else {
            value
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        }
    }
    rules.retain(|r| {
        if r["ruleTag"] == "xui-dns-allow" {
            return false;
        }
        let shape = r["type"] == "field"
            && r["outboundTag"] == "direct"
            && r.get("ip").is_some()
            && r.get("port").is_some()
            && r.as_object().is_some_and(|fields| {
                fields.iter().all(|(key, value)| {
                    matches!(key.as_str(), "type" | "outboundTag" | "ip" | "port")
                        || (key == "enabled" && value == true)
                })
            });
        let mut addresses = ips(&r["ip"]);
        addresses.sort();
        !shape
            || !groups.iter().any(|(port, group)| {
                r["port"].as_str() == Some(port.to_string().as_str()) && addresses == *group
            })
    });
    let Some(index) = rules.iter().position(|r| {
        r["outboundTag"] == "blocked"
            && ips(&r["ip"])
                .iter()
                .any(|s| s.eq_ignore_ascii_case("geoip:private"))
    }) else {
        return Ok(());
    };
    if groups.len() > 1 {
        return Err(invalid(
            "3x-ui 3.8.5 requires one private DNS port while geoip:private is blocked; reconcile panel DNS before preview",
        ));
    }
    let allow=groups.into_iter().map(|(port,ips)|json!({"type":"field","ruleTag":"xui-dns-allow","ip":ips,"port":port.to_string(),"outboundTag":"direct"}));
    rules.splice(index..index, allow);
    Ok(())
}

pub fn verify_routes(
    client: &Client,
    config: &Config,
    matrix: &Matrix,
    ingress: &[String],
) -> io::Result<()> {
    let mut tags = ingress.to_vec();
    tags.push(PROBE_TAG.into());
    for (domain, _) in rules(config) {
        let names = if domain.exact {
            vec![domain.name]
        } else {
            vec![domain.name.clone(), format!("wgates-check.{}", domain.name)]
        };
        for name in names {
            let rule = winner(config, &name).unwrap();
            let group = config
                .groups
                .iter()
                .find(|g| g.id == rule.group_id)
                .unwrap();
            for protocol in ["tcp", "udp"] {
                let ready = usable(config, group, matrix);
                let any = ready
                    && [4, 6]
                        .iter()
                        .any(|f| allowed(matrix, &group.id, &format!("{protocol}_ipv{f}")));
                let expected = if any {
                    format!(
                        "wgates-domain-{}-{protocol}",
                        group.primary.as_ref().unwrap()
                    )
                } else {
                    "wgates-block".into()
                };
                for tag in &tags {
                    if client.route_context(tag, "", Some(&name), None, protocol, 443)? != expected
                    {
                        return Err(io::Error::other(
                            "running domain rule selects an unexpected outbound",
                        ));
                    }
                    for (family, ip) in [(4, "198.51.100.253"), (6, "2001:db8:ffff::2")] {
                        let expected = if ready
                            && allowed(matrix, &group.id, &format!("{protocol}_ipv{family}"))
                        {
                            format!("wgates-out-{}", group.primary.as_ref().unwrap())
                        } else {
                            "wgates-block".into()
                        };
                        if client.route_context(tag, ip, Some(&name), None, protocol, 443)?
                            != expected
                        {
                            return Err(io::Error::other(
                                "running domain and IP rule selects an unexpected outbound",
                            ));
                        }
                    }
                }
            }
        }
    }
    for group in &config.groups {
        if !rules(config).iter().any(|(_, r)| r.group_id == group.id) {
            continue;
        }
        if let Some(connection) = connection(config, group)
            && let Some(dns) = &connection.dns
        {
            let resolver = Resolver::parse(dns)?;
            let expected = if usable(config, group, matrix) {
                format!("wgates-out-{}", connection.id)
            } else {
                "wgates-block".into()
            };
            if client.route(
                &format!("wgates-dns-{}", connection.id),
                &resolver.address.ip().to_string(),
                resolver.network,
                resolver.address.port(),
            )? != expected
            {
                return Err(io::Error::other(
                    "running DNS route selects an unexpected outbound",
                ));
            }
        }
    }
    if !rules(config).is_empty() {
        for tag in &tags {
            for protocol in ["tcp", "udp"] {
                if client.route(tag, "198.51.100.254", protocol, 53)? != "wgates-dns" {
                    return Err(io::Error::other("running DNS interception is missing"));
                }
            }
        }
    }
    Ok(())
}
