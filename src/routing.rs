use crate::panel::{Client, Settings, Snapshot};
use crate::policy::Network;
use crate::store::{self, Config, Store, private_read, private_write, random_id};
use crate::{API_VERSION, invalid, secure_directory, write_message};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};

const PREFIX: &str = "wgates-";
pub const PROBE_TAG: &str = "wgates-probe";
pub use crate::capability::ALL as CAPABILITIES;
pub type Matrix = BTreeMap<String, BTreeMap<String, String>>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub config: Config,
    pub profiles: BTreeMap<String, Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    pub port: u16,
    pub user: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub group_users: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub connection_users: BTreeMap<String, String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    id: String,
    desired_digest: String,
    panel_digest: String,
    input: Input,
    base: Snapshot,
    candidate: Snapshot,
    proxy: Proxy,
    ingress: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Working {
    plan_id: String,
    config: Config,
    snapshot: Snapshot,
    proxy: Proxy,
    matrix: Matrix,
    #[serde(default)]
    prepared_digest: Option<String>,
    #[serde(default)]
    panel_digest: Option<String>,
    #[serde(default)]
    profiles: BTreeMap<String, Value>,
    #[serde(default)]
    selected: BTreeMap<String, Option<String>>,
    #[serde(default)]
    health: BTreeMap<String, crate::health::Observation>,
    #[serde(default)]
    health_error: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionObservation {
    binding: String,
    observed_at: u64,
    source: String,
    results: BTreeMap<String, String>,
}
type ConnectionObservations = BTreeMap<String, ConnectionObservation>;
fn connection_binding(config: &Config, connection: &store::Connection) -> io::Result<String> {
    let group = config
        .groups
        .iter()
        .find(|g| g.id == connection.group_id)
        .ok_or_else(|| invalid("connection group missing"))?;
    digest(
        &json!({"profile":connection.profile_ref,"group":connection.group_id,"dns":connection.dns,"allowed":connection.allowed_capabilities,"probes":group.probes}),
    )
}
fn record_connection(
    root: &Path,
    config: &Config,
    connection: &store::Connection,
    results: BTreeMap<String, String>,
    source: &str,
) -> io::Result<()> {
    let mut records: ConnectionObservations =
        optional(&root.join("connections.json"))?.unwrap_or_default();
    records.retain(|id, _| config.connections.iter().any(|c| &c.id == id));
    records.insert(
        connection.id.clone(),
        ConnectionObservation {
            binding: connection_binding(config, connection)?,
            observed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            source: source.into(),
            results,
        },
    );
    private_write(&root.join("connections.json"), &records)
}
fn connection_verification(
    config: &Config,
    connection: &store::Connection,
    record: Option<&ConnectionObservation>,
) -> Value {
    let stale = record
        .is_some_and(|r| connection_binding(config, connection).is_ok_and(|b| b != r.binding));
    let results = record.map(|r| &r.results);
    json!({"observed_at":record.map(|r|r.observed_at),"source":record.map(|r|&r.source),"stale":stale,
        "capabilities":crate::capability::observations(&connection.allowed_capabilities, results, stale),
        "dns":crate::capability::observation(if stale{"inputs_changed"}else{results.and_then(|r|r.get("dns")).map(String::as_str).unwrap_or("not_checked")})})
}
fn connection_reports(root: &Path, config: &Config) -> io::Result<Value> {
    let records: ConnectionObservations =
        optional(&root.join("connections.json"))?.unwrap_or_default();
    Ok(Value::Object(
        config
            .connections
            .iter()
            .map(|c| {
                (
                    c.id.clone(),
                    connection_verification(config, c, records.get(&c.id)),
                )
            })
            .collect(),
    ))
}

impl Proxy {
    pub fn for_connection(&self, id: &str, group: &str) -> Self {
        Self {
            user: self
                .connection_users
                .get(id)
                .cloned()
                .unwrap_or_else(|| self.for_group(group).user),
            ..self.clone()
        }
    }
    pub fn for_group(&self, id: &str) -> Self {
        Self {
            user: self.group_users.get(id).unwrap_or(&self.user).clone(),
            ..self.clone()
        }
    }
}

pub fn digest(value: &impl Serialize) -> io::Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    serde_json::from_slice(&private_read(path, 128 * 1024 * 1024)?)
        .map_err(|_| invalid("invalid private routing state; retain and repair it offline"))
}
fn optional<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    match read(path) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
pub(crate) fn owned(value: &Value) -> bool {
    value["tag"]
        .as_str()
        .or_else(|| value["ruleTag"].as_str())
        .is_some_and(|s| s.starts_with(PREFIX))
}
fn managed(template: &Value) -> Value {
    json!({"dns_servers":template["dns"]["servers"].as_array().map(|a|a.iter().filter(|v|owned(v)).collect::<Vec<_>>()).unwrap_or_default(),"inbounds":template["inbounds"].as_array().map(|a|a.iter().filter(|v|owned(v)).collect::<Vec<_>>()).unwrap_or_default(),
        "outbounds":template["outbounds"].as_array().map(|a|a.iter().filter(|v|owned(v)).collect::<Vec<_>>()).unwrap_or_default(),
        "rules":template["routing"]["rules"].as_array().map(|a|a.iter().filter(|v|owned(v)).collect::<Vec<_>>()).unwrap_or_default()})
}
fn ingress(base: &Snapshot) -> io::Result<Vec<String>> {
    let mut tags = BTreeSet::new();
    for inbound in base
        .inbounds
        .iter()
        .filter(|v| v["enable"] == true && v["nodeId"].is_null())
        .chain(
            base.template["inbounds"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|v| !owned(v)),
        )
    {
        if inbound["protocol"] != "vless" {
            continue;
        }
        let tag = inbound["tag"]
            .as_str()
            .filter(|t| !t.is_empty() && !t.starts_with(PREFIX))
            .ok_or_else(|| invalid("VLESS ingress requires a unique non-reserved tag"))?;
        if !tags.insert(tag.to_owned()) {
            return Err(invalid("duplicate VLESS ingress tag"));
        }
        let sniffing = if let Some(s) = inbound["sniffing"].as_str() {
            if s.is_empty() {
                Value::Null
            } else {
                crate::profile::strict_json(s).map_err(|_| invalid("invalid ingress sniffing"))?
            }
        } else {
            inbound["sniffing"].clone()
        };
        if sniffing["enabled"] == true
            && sniffing["routeOnly"] != true
            && sniffing["destOverride"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
        {
            return Err(invalid(
                "unsafe VLESS sniffing replaces destination IP; set routeOnly or disable sniffing in the panel",
            ));
        }
    }
    if tags.is_empty() {
        return Err(invalid("no enabled local VLESS ingress"));
    }
    Ok(tags.into_iter().collect())
}
fn winner(config: &Config, address: std::net::IpAddr) -> Option<&str> {
    config
        .rules
        .iter()
        .filter_map(|r| {
            Network::parse(&r.destination)
                .ok()
                .filter(|n| n.contains(address))
                .map(|n| (n.prefix, r.group_id.as_str()))
        })
        .max_by_key(|(p, _)| *p)
        .map(|(_, g)| g)
}
fn validate(input: &Input, base: &Snapshot, working: Option<&Working>) -> io::Result<Vec<String>> {
    if base.template["routing"]["script"]
        .as_str()
        .is_some_and(|s| !s.is_empty())
    {
        return Err(invalid(
            "routing scripts are incompatible with managed CIDR rules",
        ));
    }
    let api = &base.template["routing"]["rules"][0];
    if api["outboundTag"] != "api"
        || !api["inboundTag"]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v == "api"))
        || api["enabled"] == false
    {
        return Err(invalid(
            "panel template requires its API rule first; re-save and reconcile it in 3x-ui before preview",
        ));
    }
    let actual = managed(&base.template);
    let expected = working
        .map(|w| managed(&w.snapshot.template))
        .unwrap_or_else(|| json!({"dns_servers":[],"inbounds":[],"outbounds":[],"rules":[]}));
    if actual != expected {
        return Err(invalid(
            "managed settings drift or reserved tag collision; reconcile before preview",
        ));
    }
    let tags = ingress(base)?;
    for v in &base.inbounds {
        if v["tag"].as_str().is_some_and(|s| s.starts_with(PREFIX)) {
            return Err(invalid("reserved tag collision in panel inbounds"));
        }
    }
    fn external_reference(value: &Value) -> bool {
        if owned(value) {
            return false;
        }
        match value {
            Value::Object(fields) => fields.iter().any(|(key, value)| {
                let references_managed =
                    |s: &str| s.starts_with(PREFIX) || (key == "selector" && PREFIX.starts_with(s));
                (matches!(
                    key.as_str(),
                    "outboundTag" | "balancerTag" | "dialerProxy" | "fallbackTag"
                ) && value.as_str().is_some_and(|s| s.starts_with(PREFIX)))
                    || (matches!(key.as_str(), "selector" | "inboundTag")
                        && (value
                            .as_str()
                            .is_some_and(|s| s.split(',').any(references_managed))
                            || value.as_array().is_some_and(|a| {
                                a.iter().filter_map(Value::as_str).any(references_managed)
                            })))
                    || external_reference(value)
            }),
            Value::Array(items) => items.iter().any(external_reference),
            _ => false,
        }
    }
    if external_reference(&base.template)
        || base.template["routing"]["balancers"]
            .as_array()
            .is_some_and(|a| a.iter().any(owned))
    {
        return Err(invalid(
            "unmanaged settings reference reserved managed tags; reconcile the panel first",
        ));
    }
    for profile in input.profiles.values() {
        if profile.get("proxySettings").is_some()
            || profile["streamSettings"]["sockopt"]["dialerProxy"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        {
            return Err(invalid(
                "VLESS primary must be standalone; outbound chains are unavailable",
            ));
        }
    }
    crate::domain::validate(input, base)?;
    for group in &input.config.groups {
        group.probes.validate()?;
    }
    crate::health::validate_groups(&input.config)?;
    Ok(tags)
}
fn initial_matrix(config: &Config) -> Matrix {
    config
        .groups
        .iter()
        .filter(|g| config.rules.iter().any(|r| r.group_id == g.id))
        .map(|g| {
            let mut result: BTreeMap<_, _> = CAPABILITIES
                .iter()
                .map(|c| {
                    (
                        c.to_string(),
                        match crate::domain::connection(config, g) {
                            None => "primary_missing",
                            Some(connection)
                                if !crate::capability::permits(
                                    &connection.allowed_capabilities,
                                    c,
                                ) =>
                            {
                                "configured_limit"
                            }
                            Some(_) if !probe_configured(g, c) => "probe_missing",
                            Some(_) => "candidate",
                        }
                        .to_owned(),
                    )
                })
                .collect();
            if crate::domain::rules(config)
                .iter()
                .any(|(_, r)| r.group_id == g.id)
            {
                let state = if g.primary.is_none() {
                    "primary_missing"
                } else if crate::domain::connection(config, g)
                    .and_then(|c| c.dns.as_ref())
                    .is_none()
                {
                    "dns_missing"
                } else if g.probes.dns.is_none() {
                    "probe_missing"
                } else if let Some(resolver) = crate::domain::connection(config, g)
                    .and_then(|c| c.dns.as_ref())
                    .and_then(|d| crate::policy::Resolver::parse(d).ok())
                {
                    if result
                        .get(&resolver.capability())
                        .is_some_and(|r| r == "configured_limit")
                    {
                        "configured_limit"
                    } else if result
                        .get(&resolver.capability())
                        .is_none_or(|r| r != "candidate")
                    {
                        "dns_transport_unverified"
                    } else {
                        "candidate"
                    }
                } else {
                    "dns_missing"
                };
                result.insert("dns".into(), state.into());
            }
            if g.healthcheck.is_some() {
                for reason in result.values_mut() {
                    *reason = "healthcheck_pending".into();
                }
            }
            (g.id.clone(), result)
        })
        .collect()
}
fn probe_configured(group: &store::Group, capability: &str) -> bool {
    match capability {
        "tcp_ipv4" => group.probes.tcp_ipv4.is_some(),
        "udp_ipv4" => group.probes.udp_ipv4.is_some(),
        "tcp_ipv6" => group.probes.tcp_ipv6.is_some(),
        "udp_ipv6" => group.probes.udp_ipv6.is_some(),
        _ => false,
    }
}
fn eligibility(config: &Config) -> Value {
    let matrix = initial_matrix(config);
    let mut result = serde_json::Map::new();
    for rule in &config.rules {
        let family = Network::parse(&rule.destination)
            .ok()
            .map(|n| if n.address.is_ipv4() { "ipv4" } else { "ipv6" });
        let mut fields = serde_json::Map::new();
        for capability in CAPABILITIES
            .into_iter()
            .filter(|c| family.is_none_or(|f| c.ends_with(f)))
        {
            let reason = matrix
                .get(&rule.group_id)
                .and_then(|r| r.get(capability))
                .map(String::as_str)
                .unwrap_or("primary_missing");
            fields.insert(
                capability.to_owned(),
                json!({"reason":if reason=="candidate"{"verification_required"}else{reason}}),
            );
        }
        if family.is_none() {
            let connection = config
                .groups
                .iter()
                .find(|g| g.id == rule.group_id)
                .and_then(|g| crate::domain::connection(config, g));
            fields.insert("dns".into(), json!({"reason":matrix[&rule.group_id].get("dns"),"requires":connection.and_then(|c|c.dns.as_ref()).and_then(|d|crate::policy::Resolver::parse(d).ok()).map(|r|r.capability())}));
        }
        result.insert(rule.id.clone(), Value::Object(fields));
    }
    Value::Object(result)
}
pub(crate) fn allowed(matrix: &Matrix, group: &str, capability: &str) -> bool {
    matrix
        .get(group)
        .and_then(|c| c.get(capability))
        .is_some_and(|s| s == "verified" || s == "candidate")
}
fn render(
    input: &Input,
    base: &Snapshot,
    proxy: &Proxy,
    tags: &[String],
    matrix: &Matrix,
) -> io::Result<Snapshot> {
    let mut result = base.clone();
    let template = &mut result.template;
    let outbounds = template["outbounds"]
        .as_array_mut()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| invalid("panel template requires existing outbounds"))?;
    outbounds.retain(|v| !owned(v));
    if outbounds.is_empty() {
        return Err(invalid(
            "no unrelated default outbound; reconcile panel template",
        ));
    }
    outbounds.extend([
        json!({"tag":"wgates-direct","protocol":"freedom","settings":{}}),
        json!({"tag":"wgates-block","protocol":"blackhole","settings":{}}),
    ]);
    for (id, profile) in &input.profiles {
        let mut profile = profile.clone();
        profile["tag"] = json!(format!("wgates-out-{id}"));
        outbounds.push(profile);
    }
    if template.get("inbounds").is_none() {
        template["inbounds"] = json!([]);
    }
    let inbounds = template["inbounds"]
        .as_array_mut()
        .ok_or_else(|| invalid("invalid template inbounds"))?;
    inbounds.retain(|v| !owned(v));
    let mut users = vec![json!({"user":proxy.user,"pass":proxy.password})];
    users.extend(
        proxy
            .group_users
            .values()
            .chain(proxy.connection_users.values())
            .map(|u| json!({"user":u,"pass":proxy.password})),
    );
    inbounds.push(json!({"tag":PROBE_TAG,"listen":"127.0.0.1","port":proxy.port,"protocol":"socks","settings":{"auth":"password","users":users,"udp":true,"ip":"127.0.0.1"}}));
    if template.get("routing").is_none() {
        template["routing"] = json!({"rules":[]});
    }
    if template["routing"].get("rules").is_none() {
        template["routing"]["rules"] = json!([]);
    }
    let previous = template["routing"]["rules"]
        .as_array()
        .ok_or_else(|| invalid("invalid panel routing rules"))?
        .iter()
        .filter(|v| !owned(v))
        .cloned()
        .collect::<Vec<_>>();
    let mut ingress = tags.to_vec();
    ingress.push(PROBE_TAG.to_owned());
    let mut rules = vec![previous[0].clone()];
    for connection in &input.config.connections {
        let Some(user) = proxy.connection_users.get(&connection.id) else {
            continue;
        };
        for protocol in ["tcp", "udp"] {
            for (family, network) in [(4, "0.0.0.0/0"), (6, "::/0")] {
                let permitted = crate::capability::permits(
                    &connection.allowed_capabilities,
                    &format!("{protocol}_ipv{family}"),
                );
                rules.push(json!({"type":"field","ruleTag":format!("wgates-check-{}-{protocol}-ipv{family}",connection.id),"inboundTag":[PROBE_TAG],"user":[user],"network":protocol,"ip":[network],"outboundTag":if permitted{format!("wgates-out-{}",connection.id)}else{"wgates-block".into()}}));
            }
        }
        rules.push(json!({"type":"field","ruleTag":format!("wgates-check-{}-block",connection.id),"inboundTag":[PROBE_TAG],"user":[user],"outboundTag":"wgates-block"}));
    }
    for (group_id, user) in &proxy.group_users {
        let group = input
            .config
            .groups
            .iter()
            .find(|g| &g.id == group_id)
            .unwrap();
        for protocol in ["tcp", "udp"] {
            for (family, network) in [(4, "0.0.0.0/0"), (6, "::/0")] {
                let primary = group
                    .primary
                    .as_ref()
                    .filter(|_| allowed(matrix, group_id, &format!("{protocol}_ipv{family}")));
                rules.push(json!({"type":"field","ruleTag":format!("wgates-probe-{group_id}-{protocol}-ipv{family}"),"inboundTag":[PROBE_TAG],"user":[user],"network":protocol,"ip":[network],"outboundTag":primary.map(|id|format!("wgates-out-{id}")).unwrap_or_else(||"wgates-block".into())}));
            }
        }
        rules.push(json!({"type":"field","ruleTag":format!("wgates-probe-{group_id}-block"),"inboundTag":[PROBE_TAG],"user":[user],"outboundTag":"wgates-block"}));
    }
    rules.extend(crate::domain::render(input, template, &ingress, matrix)?);
    let mut ordered = input
        .config
        .rules
        .iter()
        .filter_map(|r| Network::parse(&r.destination).ok().map(|n| (n, r)))
        .collect::<Vec<_>>();
    ordered.sort_by(|(a, ar), (b, br)| {
        b.prefix
            .cmp(&a.prefix)
            .then(ar.destination.cmp(&br.destination))
    });
    for (network, rule) in ordered {
        let group = input
            .config
            .groups
            .iter()
            .find(|g| g.id == rule.group_id)
            .unwrap();
        for protocol in ["tcp", "udp"] {
            let capability = format!(
                "{protocol}_ipv{}",
                if network.address.is_ipv4() { 4 } else { 6 }
            );
            if let Some(primary) = &group.primary
                && allowed(matrix, &group.id, &capability)
            {
                rules.push(json!({"type":"field","ruleTag":format!("wgates-{}-{protocol}",rule.id),"inboundTag":ingress,"ip":[rule.destination],"network":protocol,"outboundTag":format!("wgates-out-{primary}")}));
            }
        }
        rules.push(json!({"type":"field","ruleTag":format!("wgates-{}-block",rule.id),"inboundTag":ingress,"ip":[rule.destination],"outboundTag":"wgates-block"}));
    }
    rules.push(json!({"type":"field","ruleTag":"wgates-unmatched","inboundTag":ingress,"outboundTag":"wgates-direct"}));
    rules.extend(previous.into_iter().skip(1));
    template["routing"]["rules"] = json!(rules);
    crate::domain::normalise_panel_dns(template)?;
    Ok(result)
}

pub struct Service {
    root: PathBuf,
    busy: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    health_due: BTreeMap<String, std::time::Instant>,
    active_plan: Option<String>,
    reload_health: bool,
}
impl Service {
    pub fn new(state: &Path, stopping: Arc<AtomicBool>) -> io::Result<Self> {
        let root = state.join("routing");
        match std::fs::symlink_metadata(&root) {
            Ok(_) => secure_directory(&root, 0o700, 0o077)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut health_due = BTreeMap::new();
        let working: Option<Working> = optional(&root.join("working.json")).unwrap_or(None);
        let active_plan = working.as_ref().map(|w| w.plan_id.clone());
        if let Some(mut working) = working {
            if !working.health.is_empty() {
                for record in working.health.values_mut() {
                    record.successes = 0;
                    record.failures = 0;
                    record.fresh = false;
                    record.reason = "awaiting_probe".into();
                }
                private_write(&root.join("working.json"), &working)?;
            }
            for group in &working.config.groups {
                if group.healthcheck.is_some() {
                    health_due.insert(group.id.clone(), std::time::Instant::now());
                }
            }
        }
        Ok(Self {
            root,
            busy: Arc::new(AtomicBool::new(false)),
            stopping,
            worker: None,
            health_due,
            active_plan,
            reload_health: true,
        })
    }
    pub fn busy(&self) -> bool {
        self.busy.load(Ordering::Relaxed)
    }
    pub fn reap(&mut self) {
        if self.worker.as_ref().is_some_and(|w| w.is_finished()) {
            let _ = self.worker.take().unwrap().join();
            self.reload_health = true;
        }
    }
    pub fn finish(&mut self) {
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
    pub fn dispatch(
        &mut self,
        request: &Value,
        store: &Store,
        stream: &UnixStream,
    ) -> io::Result<Option<Value>> {
        let command = store::text(&request["command"])?;
        let fields: &[&str] = match command {
            "panel.configure" => &["settings"],
            "panel.preflight" | "routing.preview" | "routing.status" => &[],
            "routing.apply" | "routing.recover" => &["plan_id"],
            "connection.verify" => &["id"],
            _ => return Err(invalid("unsupported routing command")),
        };
        if request.as_object().is_none_or(|m| {
            m.keys()
                .any(|k| k != "api_version" && k != "command" && !fields.contains(&k.as_str()))
        }) {
            return Err(invalid("unexpected local API request field"));
        }
        if command == "routing.status" {
            let saved: Value = optional(&self.root.join("status.json"))?
                .unwrap_or(json!({"state":"unapplied","running_revision":null}));
            return Ok(Some(
                json!({"data":{"desired_revision":store.config().revision,"busy":self.busy(),"recovery_required":optional::<Journal>(&self.root.join("journal.json"))?.as_ref().is_some_and(pending) && !self.busy(),"last_observation":saved,"health_schedule":self.health_due.iter().map(|(group,due)|json!({"group_id":group,"due_in_seconds":due.saturating_duration_since(std::time::Instant::now()).as_secs(),"overdue_seconds":std::time::Instant::now().saturating_duration_since(*due).as_secs()})).collect::<Vec<_>>(),"health":optional::<Working>(&self.root.join("working.json"))?.map(|w|w.health_report()),"connection_verifications":connection_reports(&self.root,store.config()).unwrap_or_else(|_|json!({"state":"unknown","reason":"observation_state_unreadable"}))}}),
            ));
        }
        if self.busy() {
            return Err(io::Error::other(
                "routing operation in progress; configuration writes are locked",
            ));
        }
        secure_directory(&self.root, 0o700, 0o077)?;
        std::fs::File::open(self.root.parent().unwrap())?.sync_all()?;
        if command == "panel.configure" {
            if optional::<Journal>(&self.root.join("journal.json"))?
                .as_ref()
                .is_some_and(pending)
            {
                return Err(invalid(
                    "unfinished apply must be recovered before changing panel credentials",
                ));
            }
            let settings: Settings = serde_json::from_value(request["settings"].clone())
                .map_err(|_| invalid("invalid panel settings"))?;
            settings.validate()?;
            private_write(&self.root.join("panel.json"), &settings)?;
            return Ok(Some(json!({"data":{"configured":true}})));
        }
        let input = store.routing_input()?;
        let mut stream = stream.try_clone()?;
        let (root, command, request, busy, stopping) = (
            self.root.clone(),
            command.to_owned(),
            request.clone(),
            self.busy.clone(),
            self.stopping.clone(),
        );
        busy.store(true, Ordering::Relaxed);
        let worker = thread::Builder::new()
            .name("routing".to_owned())
            .spawn(move || {
                struct Guard(Arc<AtomicBool>);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::Relaxed);
                    }
                }
                let _guard = Guard(busy);
                let result = execute(&root, &command, &request, input, stopping);
                let response = match result {
                    Ok(data) => json!({"api_version":API_VERSION,"data":data}),
                    Err(e) => json!({"api_version":API_VERSION,"error":e.to_string()}),
                };
                let _ = write_message(&mut stream, &response);
            });
        match worker {
            Ok(worker) => {
                self.worker = Some(worker);
                Ok(None)
            }
            Err(e) => {
                self.busy.store(false, Ordering::Relaxed);
                Err(e)
            }
        }
    }
}
fn execute(
    root: &Path,
    command: &str,
    request: &Value,
    input: Input,
    stopping: Arc<AtomicBool>,
) -> io::Result<Value> {
    let settings: Settings = read(&root.join("panel.json"))?;
    let panel_digest = digest(&settings)?;
    let client = Client::new(settings, stopping)?;
    if command == "panel.preflight" {
        let status = client.running()?;
        client.read()?;
        return Ok(status);
    }
    if command == "connection.verify" {
        if optional::<Journal>(&root.join("journal.json"))?
            .as_ref()
            .is_some_and(pending)
        {
            return Err(invalid(
                "unfinished apply requires routing recover before verification",
            ));
        }
        let connection = input
            .config
            .connections
            .iter()
            .find(|c| request["id"] == c.id)
            .ok_or_else(|| invalid("connection not found"))?;
        let working: Option<Working> = optional(&root.join("working.json"))?;
        let working = working
            .filter(|w| {
                w.prepared_digest
                    .as_ref()
                    .is_some_and(|d| digest(&input).is_ok_and(|v| &v == d))
                    && w.panel_digest.as_ref() == Some(&panel_digest)
                    && w.proxy.connection_users.contains_key(&connection.id)
            })
            .ok_or_else(|| {
                invalid("connection verification requires a current routing preview and apply")
            })?;
        client.running()?;
        if client.read()? != working.snapshot {
            return Err(invalid(
                "observed panel drift; preview and apply before verification",
            ));
        }
        let results = crate::probe::connection(&client, &input.config, connection, &working.proxy)?;
        if client.read()? != working.snapshot {
            return Err(invalid(
                "observed panel drift during verification; observations were not saved",
            ));
        }
        record_connection(root, &input.config, connection, results, "connection")?;
        let reports = connection_reports(root, &input.config)?;
        return Ok(
            json!({"connection_id":connection.id,"verification":reports[&connection.id],"policy_effect":"observations_only"}),
        );
    }
    if command == "routing.preview" {
        if let Some(journal) = optional::<Journal>(&root.join("journal.json"))?
            && pending(&journal)
        {
            return Err(invalid(
                "unfinished apply requires routing recover before another preview",
            ));
        }
        client.running()?;
        let base = client.read()?;
        let working: Option<Working> = optional(&root.join("working.json"))?;
        let ingress = validate(&input, &base, working.as_ref())?;
        let mut proxy = match working {
            Some(w) => w.proxy,
            None => Proxy {
                port: TcpListener::bind("127.0.0.1:0")?.local_addr()?.port(),
                user: random_id()?,
                password: random_id()?,
                group_users: BTreeMap::new(),
                connection_users: BTreeMap::new(),
            },
        };
        proxy
            .group_users
            .retain(|id, _| input.config.rules.iter().any(|r| &r.group_id == id));
        for group in input
            .config
            .groups
            .iter()
            .filter(|g| input.config.rules.iter().any(|r| r.group_id == g.id))
        {
            if !proxy.group_users.contains_key(&group.id) {
                proxy.group_users.insert(group.id.clone(), random_id()?);
            }
        }
        proxy
            .connection_users
            .retain(|id, _| input.config.connections.iter().any(|c| &c.id == id));
        for connection in &input.config.connections {
            if !proxy.connection_users.contains_key(&connection.id) {
                proxy
                    .connection_users
                    .insert(connection.id.clone(), random_id()?);
            }
        }
        let candidate = render(
            &input,
            &base,
            &proxy,
            &ingress,
            &initial_matrix(&input.config),
        )?;
        let plan = Plan {
            id: random_id()?,
            desired_digest: digest(&input)?,
            panel_digest,
            input,
            base,
            candidate,
            proxy,
            ingress,
        };
        private_write(&root.join("plan.json"), &plan)?;
        return Ok(
            json!({"plan_id":plan.id,"desired_revision":plan.input.config.revision,"ingress":plan.ingress,"rules":plan.input.config.rules,
            "dns":crate::domain::describe(&plan.input.config),"panel_dns_rules":plan.candidate.template["routing"]["rules"].as_array().map(|a|a.iter().filter(|v|v["ruleTag"]=="xui-dns-allow").collect::<Vec<_>>()),"capabilities":"conditional_on_runtime_probes","prepared_connections":plan.input.config.connections.iter().map(|c|&c.id).collect::<Vec<_>>(),"eligibility":eligibility(&plan.input.config),"automatic_groups":plan.input.config.groups.iter().filter(|g|g.healthcheck.is_some()).map(|g|json!({"group_id":g.id,"primary":g.primary,"fallbacks":g.fallbacks,"healthcheck":g.healthcheck})).collect::<Vec<_>>(),"unmatched":"direct","unverified":"blocked","sessions_may_interrupt":true}),
        );
    }
    if command == "routing.recover" {
        let mut journal: Journal = read(&root.join("journal.json"))?;
        if request["plan_id"].as_str() != Some(&journal.plan.id)
            || journal.plan.panel_digest != panel_digest
        {
            return Err(invalid("recovery plan or panel identity does not match"));
        }
        if journal.phase == "complete" {
            return Err(invalid(
                "completed apply cannot be recovered; create a new preview",
            ));
        }
        return recover(root, &client, &mut journal);
    }
    let plan: Plan = read(&root.join("plan.json"))?;
    if request["plan_id"].as_str() != Some(&plan.id) {
        return Err(invalid("unknown or superseded plan; preview again"));
    }
    if digest(&input)? != plan.desired_digest || panel_digest != plan.panel_digest {
        return Err(invalid(
            "desired state or panel credentials changed; preview again",
        ));
    }
    if let Some(journal) = optional::<Journal>(&root.join("journal.json"))?
        && pending(&journal)
    {
        return Err(invalid(
            "unfinished apply requires routing recover before another apply",
        ));
    }
    if input
        .config
        .connections
        .iter()
        .any(|c| !plan.proxy.connection_users.contains_key(&c.id))
    {
        return Err(invalid(
            "plan predates connection verification; preview again; no changes applied",
        ));
    }
    let previous: Option<Working> = optional(&root.join("working.json"))?;
    if let Some(w) = &previous
        && w.plan_id == plan.id
    {
        verify(
            &client,
            &w.snapshot,
            &w.effective_config(),
            &w.proxy,
            &w.matrix,
            &plan.ingress,
            Some(&w.health),
        )?;
        return Ok(observation(&plan.id, &w.config, &w.snapshot, &w.matrix));
    }
    client.running()?;
    if client.read()? != plan.base {
        return Err(invalid(
            "observed panel drift; preview again; no changes applied",
        ));
    }
    let mut journal = Journal {
        plan,
        submitted: Vec::new(),
        previous,
        phase: "applying".to_owned(),
    };
    private_write(&root.join("journal.json"), &journal)?;
    private_write(
        &root.join("status.json"),
        &json!({"state":"applying","plan_id":journal.plan.id,"desired_revision":input.config.revision,"running_revision":journal.previous.as_ref().map(|w|w.config.revision)}),
    )?;
    let result = (|| -> io::Result<Value> {
        let candidate = journal.plan.candidate.clone();
        submit(root, &client, &mut journal, &candidate)?;
        wait_routes(
            &client,
            &input.config,
            &initial_matrix(&input.config),
            &journal.plan.ingress,
        )?;
        let mut legacy = input.config.clone();
        legacy.rules.retain(|r| {
            !input
                .config
                .groups
                .iter()
                .any(|g| g.id == r.group_id && g.healthcheck.is_some())
        });
        let mut matrix = crate::probe::check(&client, &legacy, &journal.plan.proxy, None)?;
        let mut health = BTreeMap::new();
        let mut verifications = BTreeMap::new();
        for connection in &input.config.connections {
            let group = input
                .config
                .groups
                .iter()
                .find(|g| g.id == connection.group_id)
                .unwrap();
            if let Some(policy) = &group.healthcheck {
                let admitted = crate::probe::connection(
                    &client,
                    &input.config,
                    connection,
                    &journal.plan.proxy,
                )?;
                let results =
                    crate::probe::health(&client, &input.config, connection, &journal.plan.proxy)?;
                verifications.insert(connection.id.clone(), admitted.clone());
                let mut record = crate::health::Observation {
                    admitted: admitted.clone(),
                    ..Default::default()
                };
                if let Some(previous) = &journal.previous
                    && let Some(old_connection) = previous
                        .config
                        .connections
                        .iter()
                        .find(|c| c.id == connection.id)
                    && let Some(old_group) =
                        previous.config.groups.iter().find(|g| g.id == group.id)
                    && connection_binding(&previous.config, old_connection)?
                        == connection_binding(&input.config, connection)?
                    && digest(&old_group.healthcheck)? == digest(&group.healthcheck)?
                    && let Some(old) = previous.health.get(&connection.id)
                {
                    record = old.clone();
                    let mut retained = policy.required_capabilities.clone();
                    retained.push("dns".into());
                    if let Some(server) = &connection.dns {
                        retained.push(crate::policy::Resolver::parse(server)?.capability());
                    }
                    record
                        .admitted
                        .extend(admitted.into_iter().filter(|(c, _)| !retained.contains(c)));
                }
                record.record(results, policy);
                health.insert(connection.id.clone(), record);
            }
        }
        let selected = select(&input.config, &health);
        let effective = effective_config(&input.config, &selected);
        select_matrix(&input.config, &selected, &health, &mut matrix);
        let final_snapshot = render(
            &Input {
                config: effective.clone(),
                profiles: input.profiles.clone(),
            },
            &journal.plan.base,
            &journal.plan.proxy,
            &journal.plan.ingress,
            &matrix,
        )?;
        if final_snapshot != candidate {
            submit(root, &client, &mut journal, &final_snapshot)?;
        }
        verify(
            &client,
            &final_snapshot,
            &effective,
            &journal.plan.proxy,
            &matrix,
            &journal.plan.ingress,
            Some(&health),
        )?;
        let working = Working {
            plan_id: journal.plan.id.clone(),
            config: input.config.clone(),
            snapshot: final_snapshot.clone(),
            proxy: journal.plan.proxy.clone(),
            matrix,
            prepared_digest: Some(digest(&input)?),
            panel_digest: Some(panel_digest.clone()),
            profiles: input.profiles.clone(),
            selected,
            health,
            health_error: None,
        };
        let report = observation(
            &working.plan_id,
            &working.config,
            &working.snapshot,
            &working.matrix,
        );
        for connection in &input.config.connections {
            if let Some(results) = verifications.get(&connection.id) {
                record_connection(root, &input.config, connection, results.clone(), "apply")?;
            }
        }
        let effective = working.effective_config();
        for group in effective.groups.iter().filter(|g| g.healthcheck.is_none()) {
            if let Some(connection) = crate::domain::connection(&input.config, group)
                && let Some(results) = working.matrix.get(&group.id)
            {
                record_connection(root, &input.config, connection, results.clone(), "apply")?;
            }
        }
        private_write(&root.join("working.json"), &working)?;
        private_write(&root.join("status.json"), &report)?;
        journal.phase = "complete".to_owned();
        private_write(&root.join("journal.json"), &journal)?;
        Ok(report)
    })();
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            if journal.submitted.is_empty() {
                journal.phase = "rejected".to_owned();
                private_write(&root.join("journal.json"), &journal)?;
                private_write(
                    &root.join("status.json"),
                    &json!({"state":"rejected","plan_id":journal.plan.id,"mismatch":true}),
                )?;
                return Err(error);
            }
            if client.cancelled() {
                recovery_required(root, &mut journal)?;
                return Err(io::Error::other(
                    "apply interrupted; inspect routing status and recover the recorded plan",
                ));
            }
            match recover(root, &client, &mut journal) {
                Ok(report) => Err(io::Error::other(format!(
                    "apply failed: {error}; recovery state: {}",
                    report["state"].as_str().unwrap_or("unknown")
                ))),
                Err(_) => Err(io::Error::other(
                    "apply failed; recovery requires inspection; saved and running state may differ; no further writes attempted",
                )),
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    plan: Plan,
    submitted: Vec<Snapshot>,
    previous: Option<Working>,
    phase: String,
}
fn pending(j: &Journal) -> bool {
    !matches!(j.phase.as_str(), "complete" | "restored" | "rejected")
}
fn submit(
    root: &Path,
    client: &Client,
    journal: &mut Journal,
    snapshot: &Snapshot,
) -> io::Result<()> {
    let expected = journal.submitted.last().unwrap_or(&journal.plan.base);
    if &client.read()? != expected {
        return Err(invalid("observed panel drift before write"));
    }
    journal.submitted.push(snapshot.clone());
    private_write(&root.join("journal.json"), journal)?;
    client.update(snapshot)?;
    if client.read()? != *snapshot {
        return Err(io::Error::other(
            "saved panel settings do not match submitted candidate",
        ));
    }
    Ok(())
}
fn verify(
    client: &Client,
    snapshot: &Snapshot,
    config: &Config,
    proxy: &Proxy,
    matrix: &Matrix,
    ingress: &[String],
    health: Option<&BTreeMap<String, crate::health::Observation>>,
) -> io::Result<()> {
    if client.read()? != *snapshot {
        return Err(invalid("observed panel drift during verification"));
    }
    wait_routes(client, config, matrix, ingress)?;
    let mut verified = matrix.clone();
    for group in config.groups.iter().filter(|g| g.healthcheck.is_some()) {
        if let Some(record) = health.and_then(|h| group.primary.as_ref().and_then(|id| h.get(id)))
            && record.fresh
            && record.available
            && record.failures > 0
            && let Some(combinations) = verified.get_mut(&group.id)
        {
            for (capability, reason) in combinations {
                if record
                    .results
                    .get(capability)
                    .is_none_or(|r| r != "verified")
                {
                    *reason = "not_rechecked".into();
                }
            }
        }
    }
    crate::probe::check(client, config, proxy, Some(&verified))?;
    if client.read()? != *snapshot {
        return Err(invalid("observed panel drift after traffic verification"));
    }
    Ok(())
}
fn verify_routes(
    client: &Client,
    config: &Config,
    matrix: &Matrix,
    ingress: &[String],
) -> io::Result<()> {
    let mut tags = ingress.to_vec();
    tags.push(PROBE_TAG.to_owned());
    for rule in &config.rules {
        let Ok(network) = Network::parse(&rule.destination) else {
            continue;
        };
        let bits = if network.address.is_ipv4() { 32 } else { 128 };
        let number = match network.address {
            std::net::IpAddr::V4(a) => u32::from(a) as u128,
            std::net::IpAddr::V6(a) => u128::from(a),
        };
        let mask = if network.prefix == 0 {
            if bits == 32 {
                u32::MAX as u128
            } else {
                u128::MAX
            }
        } else {
            (1_u128 << (bits - network.prefix)) - 1
        };
        let last = if bits == 32 {
            std::net::IpAddr::V4(((number | mask) as u32).into())
        } else {
            std::net::IpAddr::V6((number | mask).into())
        };
        for address in [network.address, last] {
            let group =
                winner(config, address).ok_or_else(|| invalid("invalid desired rule coverage"))?;
            for protocol in ["tcp", "udp"] {
                let capability = format!("{protocol}_ipv{}", if address.is_ipv4() { 4 } else { 6 });
                let primary = config
                    .groups
                    .iter()
                    .find(|g| g.id == group)
                    .and_then(|g| g.primary.as_ref());
                let expected = if allowed(matrix, group, &capability) {
                    format!(
                        "wgates-out-{}",
                        primary.ok_or_else(|| invalid("missing primary"))?
                    )
                } else {
                    "wgates-block".to_owned()
                };
                for tag in &tags {
                    if client.route(tag, &address.to_string(), protocol, 443)? != expected {
                        return Err(io::Error::other(
                            "running rule selects an unexpected outbound",
                        ));
                    }
                }
            }
        }
    }
    crate::domain::verify_routes(client, config, matrix, ingress)?;
    for address in ["198.51.100.254", "2001:db8:ffff::1"] {
        if winner(config, address.parse().unwrap()).is_none() {
            for tag in &tags {
                for protocol in ["tcp", "udp"] {
                    if client.route(tag, address, protocol, 443)? != "wgates-direct" {
                        return Err(io::Error::other("unmatched runtime route is not direct"));
                    }
                }
            }
        }
    }
    Ok(())
}
fn wait_routes(
    client: &Client,
    config: &Config,
    matrix: &Matrix,
    ingress: &[String],
) -> io::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        client.check()?;
        let result = (|| {
            if client.status()?["running"] != true {
                return Err(io::Error::other("Xray is not running after apply"));
            }
            verify_routes(client, config, matrix, ingress)
        })();
        match result {
            Ok(()) => return Ok(()),
            Err(error) if std::time::Instant::now() >= deadline => return Err(error),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
}

fn observation(id: &str, config: &Config, snapshot: &Snapshot, matrix: &Matrix) -> Value {
    let verified = matrix
        .values()
        .flat_map(|v| v.values())
        .filter(|v| v.as_str() == "verified")
        .count();
    let total: usize = matrix.values().map(BTreeMap::len).sum();
    json!({"state":if total>0&&verified==0{"blocked"}else if verified<total{"partial"}else{"applied"},"plan_id":id,
        "desired_revision":config.revision,"running_revision":config.revision,"saved_digest":digest(snapshot).ok(),"capabilities":matrix,
        "mismatch":false,"runtime_verification":if verified>0{"traffic_and_routes"}else{"blocked_routes_only"},
        "observed_at":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()})
}
fn recovery_required(root: &Path, journal: &mut Journal) -> io::Result<()> {
    journal.phase = "recovery_required".to_owned();
    private_write(&root.join("journal.json"), journal)?;
    private_write(
        &root.join("status.json"),
        &json!({"state":"recovery_required","plan_id":journal.plan.id,
        "desired_revision":journal.plan.input.config.revision,"running_revision":null,"mismatch":true,"saved":"unknown","running":"unknown"}),
    )
}
fn recover(root: &Path, client: &Client, journal: &mut Journal) -> io::Result<Value> {
    recovery_required(root, journal)?;
    let actual = client.read()?;
    if actual != journal.plan.base {
        if !journal.submitted.contains(&actual) {
            return Err(invalid(
                "intervening panel edits prevent restoration; retain state and reconcile manually",
            ));
        }
        if client.read()? != actual {
            return Err(invalid(
                "panel changed before restoration; no overwrite attempted",
            ));
        }
        journal.phase = "restoring".to_owned();
        private_write(&root.join("journal.json"), journal)?;
        let update = client.update(&journal.plan.base);
        let restored = client.read()?;
        if restored != journal.plan.base {
            return Err(update
                .err()
                .unwrap_or_else(|| io::Error::other("saved restoration could not be confirmed")));
        }
    }
    let runtime_error = if let Some(previous) = &journal.previous {
        verify(
            client,
            &journal.plan.base,
            &previous.effective_config(),
            &previous.proxy,
            &previous.matrix,
            &journal.plan.ingress,
            None,
        )
        .err()
        .map(|error| error.to_string())
    } else {
        Some("no previously verified snapshot".into())
    };
    let runtime_verified = runtime_error.is_none();
    if let Some(previous) = &journal.previous {
        let mut previous = previous.clone();
        if !previous.health.is_empty() {
            previous.health_error = Some(
                "recovery restored previous policy; preview and apply before resuming healthchecks"
                    .into(),
            );
            for record in previous.health.values_mut() {
                record.fresh = false;
                record.successes = 0;
                record.failures = 0;
            }
        }
        private_write(&root.join("working.json"), &previous)?;
    } else if let Some(current) = optional::<Working>(&root.join("working.json"))? {
        if current.plan_id != journal.plan.id {
            return Err(invalid(
                "working snapshot changed; retain it for manual recovery",
            ));
        }
        std::fs::remove_file(root.join("working.json"))?;
        std::fs::File::open(root)?.sync_all()?;
    }
    journal.phase = "restored".to_owned();
    private_write(&root.join("journal.json"), journal)?;
    let report = json!({"state":if runtime_verified{"restored"}else{"restored_runtime_unverified"},"plan_id":journal.plan.id,
        "desired_revision":journal.plan.input.config.revision,"running_revision":if runtime_verified{journal.previous.as_ref().map(|w|w.config.revision)}else{None},
        "runtime_verification_error":runtime_error,"saved":"restored","running":if runtime_verified{"verified_previous"}else{"unverified"},"mismatch":true});
    private_write(&root.join("status.json"), &report)?;
    Ok(report)
}

impl Service {
    pub fn describe_connections(&self, response: &mut Value, config: &Config) {
        let inspected = (|| -> io::Result<(bool, Option<Working>)> {
            let pending = optional::<Journal>(&self.root.join("journal.json"))?
                .as_ref()
                .is_some_and(pending);
            Ok((pending, optional(&self.root.join("working.json"))?))
        })();
        let records: io::Result<Option<ConnectionObservations>> =
            optional(&self.root.join("connections.json"));
        let describe = |value: &mut Value| {
            let fields = match &inspected {
                Err(_) => {
                    json!({"runtime":"unknown","runtime_reason":"routing_state_unreadable","capabilities":[]})
                }
                Ok((true, _)) => {
                    json!({"runtime":"unknown","runtime_reason":"apply_or_recovery_pending","capabilities":[]})
                }
                Ok((false, None)) => {
                    json!({"runtime":"unavailable","runtime_reason":"not_applied","capabilities":[]})
                }
                Ok((false, Some(w))) if w.config.revision != config.revision => {
                    json!({"runtime":"pending_apply","runtime_reason":"desired_state_changed","capabilities":[],"running_revision":w.config.revision})
                }
                Ok((false, Some(w))) => {
                    let selected = config
                        .connections
                        .iter()
                        .find(|c| value["id"] == c.id)
                        .filter(|c| {
                            w.config
                                .connections
                                .iter()
                                .any(|old| old.id == c.id && old.profile_ref == c.profile_ref)
                                && w.config.groups.iter().any(|g| {
                                    g.id == c.group_id
                                        && w.selected
                                            .get(&g.id)
                                            .map(|v| v.as_deref())
                                            .unwrap_or(g.primary.as_deref())
                                            == Some(&c.id)
                                })
                        });
                    let capabilities: Vec<_> = selected
                        .and_then(|c| w.matrix.get(&c.group_id))
                        .map(|m| {
                            m.iter()
                                .filter(|(_, v)| v.as_str() == "verified")
                                .map(|(k, _)| k.clone())
                                .collect()
                        })
                        .unwrap_or_default();
                    json!({"runtime":if capabilities.is_empty(){"unavailable"}else{"applied"},"runtime_reason":if selected.is_some(){"last_apply_observation"}else{"not_selected"},"capabilities":capabilities,"running_revision":w.config.revision})
                }
            };
            if let Some(object) = value.as_object_mut() {
                object.extend(fields.as_object().unwrap().clone());
                if let Ok((_, Some(working))) = &inspected
                    && let Some(id) = object.get("id").and_then(Value::as_str)
                    && let Some(record) = working.health.get(id)
                {
                    object.insert("health".into(), record.describe());
                }
                if let Some(connection) = config
                    .connections
                    .iter()
                    .find(|c| object.get("id").is_some_and(|v| v == &c.id))
                {
                    match &records {
                        Ok(records) => {
                            let record = records.as_ref().and_then(|r| r.get(&connection.id));
                            object.insert(
                                "verification".into(),
                                connection_verification(config, connection, record),
                            );
                            if let Some(record) = record {
                                let authentication = if connection_binding(config, connection)
                                    .is_ok_and(|b| b == record.binding)
                                {
                                    if record.results.values().any(|v| v == "verified") {
                                        "traffic_verified"
                                    } else if record
                                        .results
                                        .values()
                                        .any(|v| v.starts_with("probe_failed:"))
                                    {
                                        "unknown"
                                    } else {
                                        "not_attempted"
                                    }
                                } else {
                                    "unknown"
                                };
                                object.insert("authentication".into(), json!(authentication));
                            }
                        }
                        Err(_) => {
                            object.insert(
                                "verification".into(),
                                json!({"state":"unknown","reason":"observation_state_unreadable"}),
                            );
                            object.insert("authentication".into(), json!("unknown"));
                        }
                    }
                }
            }
        };
        if let Some(items) = response["data"].as_array_mut() {
            for value in items {
                describe(value);
            }
        } else {
            describe(&mut response["data"]);
        }
    }
}

fn effective_config(config: &Config, selected: &BTreeMap<String, Option<String>>) -> Config {
    let mut config = config.clone();
    for group in &mut config.groups {
        if let Some(connection) = selected.get(&group.id) {
            group.primary = connection.clone();
        }
    }
    config
}
fn select(
    config: &Config,
    health: &BTreeMap<String, crate::health::Observation>,
) -> BTreeMap<String, Option<String>> {
    config
        .groups
        .iter()
        .filter(|g| g.healthcheck.is_some())
        .map(|g| {
            let selected = g
                .primary
                .iter()
                .chain(g.fallbacks.iter())
                .find(|id| health.get(*id).is_some_and(|r| r.available && r.fresh))
                .cloned();
            (g.id.clone(), selected)
        })
        .collect()
}
fn select_matrix(
    config: &Config,
    selected: &BTreeMap<String, Option<String>>,
    health: &BTreeMap<String, crate::health::Observation>,
    matrix: &mut Matrix,
) {
    for group in config.groups.iter().filter(|g| g.healthcheck.is_some()) {
        let result = selected
            .get(&group.id)
            .and_then(|v| v.as_ref())
            .and_then(|id| health.get(id))
            .map(|r| r.admitted.clone())
            .unwrap_or_else(|| {
                CAPABILITIES
                    .into_iter()
                    .chain(["dns"])
                    .map(|c| (c.into(), "no_eligible_connection".into()))
                    .collect()
            });
        let mut result = result;
        if !crate::domain::rules(config)
            .iter()
            .any(|(_, r)| r.group_id == group.id)
        {
            result.remove("dns");
        }
        matrix.insert(group.id.clone(), result);
    }
}
impl Working {
    fn effective_config(&self) -> Config {
        effective_config(&self.config, &self.selected)
    }
    fn health_report(&self) -> Value {
        json!({"plan_id":self.plan_id,"running_revision":self.config.revision,"error":self.health_error,
            "groups":self.config.groups.iter().filter(|g|g.healthcheck.is_some()).map(|g|{
                let selected=self.selected.get(&g.id).and_then(|v|v.as_ref());
                json!({"group_id":g.id,"selected_connection":selected,"reason":if selected==g.primary.as_ref(){"primary"}else if selected.is_some(){"fallback"}else{"no_eligible_connection"},"required_capabilities":g.healthcheck.as_ref().unwrap().required_capabilities,
                "connections":self.config.connections.iter().filter(|c|c.group_id==g.id).map(|c|(c.id.clone(),self.health.get(&c.id).map(|r|r.describe()).unwrap_or(json!({"state":"unknown"})))).collect::<BTreeMap<_,_>>()})
            }).collect::<Vec<_>>()})
    }
}
impl Service {
    pub fn tick(&mut self) {
        if self.busy() || self.stopping.load(Ordering::Relaxed) {
            return;
        }
        if !self.reload_health
            && self
                .health_due
                .values()
                .all(|due| *due > std::time::Instant::now())
        {
            return;
        }
        self.reload_health = false;
        let ready = (|| -> io::Result<Option<(Working, Vec<String>)>> {
            if optional::<Journal>(&self.root.join("journal.json"))?
                .as_ref()
                .is_some_and(pending)
            {
                self.health_due.clear();
                return Ok(None);
            }
            let Some(working) = optional::<Working>(&self.root.join("working.json"))? else {
                return Ok(None);
            };
            if working.health_error.is_some() || working.profiles.is_empty() {
                self.health_due.clear();
                return Ok(None);
            }
            let now = std::time::Instant::now();
            if self.active_plan.as_ref() != Some(&working.plan_id) {
                self.active_plan = Some(working.plan_id.clone());
                self.health_due.clear();
                for group in &working.config.groups {
                    if let Some(check) = &group.healthcheck {
                        self.health_due.insert(
                            group.id.clone(),
                            now + std::time::Duration::from_secs(check.interval_seconds),
                        );
                    }
                }
            }
            let mut due = Vec::new();
            for group in &working.config.groups {
                if let Some(check) = &group.healthcheck {
                    let next = self.health_due.entry(group.id.clone()).or_insert(now);
                    if *next <= now {
                        due.push(group.id.clone());
                        *next = now + std::time::Duration::from_secs(check.interval_seconds);
                    }
                }
            }
            Ok(if due.is_empty() {
                None
            } else {
                Some((working, due))
            })
        })();
        let (working, due) = match ready {
            Ok(Some(v)) => v,
            _ => return,
        };
        let root = self.root.clone();
        let busy = self.busy.clone();
        let stopping = self.stopping.clone();
        busy.store(true, Ordering::Relaxed);
        match thread::Builder::new()
            .name("healthcheck".into())
            .spawn(move || {
                let result = health_cycle(&root, working, due, stopping.clone());
                if let Err(error) = result {
                    eprintln!("wgates: healthcheck stopped: {error}");
                    if !stopping.load(Ordering::Relaxed)
                        && let Ok(Some(mut working)) =
                            optional::<Working>(&root.join("working.json"))
                    {
                        working.health_error = Some(error.to_string());
                        let _ = private_write(&root.join("working.json"), &working);
                    }
                }
                busy.store(false, Ordering::Relaxed);
            }) {
            Ok(worker) => self.worker = Some(worker),
            Err(_) => self.busy.store(false, Ordering::Relaxed),
        }
    }
}
fn health_cycle(
    root: &Path,
    mut working: Working,
    due: Vec<String>,
    stopping: Arc<AtomicBool>,
) -> io::Result<()> {
    let settings: Settings = read(&root.join("panel.json"))?;
    if working.panel_digest.as_ref() != Some(&digest(&settings)?) {
        return Err(invalid(
            "panel identity changed; preview and apply before healthchecks",
        ));
    }
    let client = Client::new(settings, stopping)?;
    client.running()?;
    if client.read()? != working.snapshot {
        return Err(invalid("observed panel drift; automatic writes stopped"));
    }
    for connection in &working.config.connections {
        if !due.contains(&connection.group_id) {
            continue;
        }
        let group = working
            .config
            .groups
            .iter()
            .find(|g| g.id == connection.group_id)
            .unwrap();
        let check = group.healthcheck.as_ref().unwrap();
        let results = crate::probe::health(&client, &working.config, connection, &working.proxy)?;
        working
            .health
            .get_mut(&connection.id)
            .ok_or_else(|| invalid("health state missing; preview and apply again"))?
            .record(results, check);
    }
    if client.read()? != working.snapshot {
        return Err(invalid(
            "observed panel drift during healthcheck; automatic writes stopped",
        ));
    }
    let selected = select(&working.config, &working.health);
    let mut matrix = working.matrix.clone();
    select_matrix(&working.config, &selected, &working.health, &mut matrix);
    if selected == working.selected && matrix == working.matrix {
        private_write(&root.join("working.json"), &working)?;
        return Ok(());
    }
    let effective = effective_config(&working.config, &selected);
    let input = Input {
        config: effective.clone(),
        profiles: working.profiles.clone(),
    };
    let ingress = ingress(&working.snapshot)?;
    let candidate = render(&input, &working.snapshot, &working.proxy, &ingress, &matrix)?;
    let previous: Working = read(&root.join("working.json"))?;
    let plan = Plan {
        id: random_id()?,
        desired_digest: digest(&input)?,
        panel_digest: working.panel_digest.clone().unwrap(),
        input,
        base: working.snapshot.clone(),
        candidate: candidate.clone(),
        proxy: working.proxy.clone(),
        ingress: ingress.clone(),
    };
    let mut journal = Journal {
        plan,
        submitted: Vec::new(),
        previous: Some(previous),
        phase: "applying".into(),
    };
    private_write(&root.join("journal.json"), &journal)?;
    let result = (|| -> io::Result<()> {
        submit(root, &client, &mut journal, &candidate)?;
        verify(
            &client,
            &candidate,
            &effective,
            &working.proxy,
            &matrix,
            &ingress,
            Some(&working.health),
        )?;
        working.snapshot = candidate;
        working.selected = selected;
        working.matrix = matrix;
        private_write(&root.join("working.json"), &working)?;
        private_write(
            &root.join("status.json"),
            &observation(
                &working.plan_id,
                &effective,
                &working.snapshot,
                &working.matrix,
            ),
        )?;
        journal.phase = "complete".into();
        private_write(&root.join("journal.json"), &journal)
    })();
    if let Err(error) = result {
        if client.cancelled() {
            recovery_required(root, &mut journal)?;
        } else {
            let _ = recover(root, &client, &mut journal);
        }
        return Err(io::Error::other(format!(
            "automatic switch failed: {error}; inspect routing status and recover the recorded plan if required"
        )));
    }
    Ok(())
}
