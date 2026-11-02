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
pub const CAPABILITIES: [&str; 4] = ["tcp_ipv4", "udp_ipv4", "tcp_ipv6", "udp_ipv6"];
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
fn owned(value: &Value) -> bool {
    value["tag"]
        .as_str()
        .or_else(|| value["ruleTag"].as_str())
        .is_some_and(|s| s.starts_with(PREFIX))
}
fn managed(template: &Value) -> Value {
    json!({"inbounds":template["inbounds"].as_array().map(|a|a.iter().filter(|v|owned(v)).collect::<Vec<_>>()).unwrap_or_default(),
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
        .unwrap_or_else(|| json!({"inbounds":[],"outbounds":[],"rules":[]}));
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
                (matches!(key.as_str(), "outboundTag" | "balancerTag" | "dialerProxy")
                    && value.as_str().is_some_and(|s| s.starts_with(PREFIX)))
                    || (key == "inboundTag"
                        && value.as_array().is_some_and(|a| {
                            a.iter()
                                .any(|v| v.as_str().is_some_and(|s| s.starts_with(PREFIX)))
                        }))
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
    for group in input
        .config
        .groups
        .iter()
        .filter(|g| input.config.rules.iter().any(|r| r.group_id == g.id))
    {
        group.probes.validate()?;
        let addresses = [
            group.probes.tcp_ipv4.as_ref().map(|p| p.address()),
            group.probes.tcp_ipv6.as_ref().map(|p| p.address()),
            group
                .probes
                .udp_ipv4
                .as_ref()
                .map(|p| p.address().map(|a| a.ip())),
            group
                .probes
                .udp_ipv6
                .as_ref()
                .map(|p| p.address().map(|a| a.ip())),
        ];
        for address in addresses.into_iter().flatten() {
            if winner(&input.config, address?) != Some(group.id.as_str()) {
                return Err(invalid(
                    "probe destination must select its group under the most-specific rule",
                ));
            }
        }
    }
    Ok(tags)
}
fn initial_matrix(config: &Config) -> Matrix {
    config
        .groups
        .iter()
        .filter(|g| config.rules.iter().any(|r| r.group_id == g.id))
        .map(|g| {
            (
                g.id.clone(),
                CAPABILITIES
                    .iter()
                    .map(|c| {
                        (
                            c.to_string(),
                            if g.primary.is_some() {
                                "candidate"
                            } else {
                                "primary_missing"
                            }
                            .to_owned(),
                        )
                    })
                    .collect(),
            )
        })
        .collect()
}
fn allowed(matrix: &Matrix, group: &str, capability: &str) -> bool {
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
    inbounds.push(json!({"tag":PROBE_TAG,"listen":"127.0.0.1","port":proxy.port,"protocol":"socks","settings":{"auth":"password","users":[{"user":proxy.user,"pass":proxy.password}],"udp":true,"ip":"127.0.0.1"}}));
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
    let mut ordered = input
        .config
        .rules
        .iter()
        .map(|r| Ok((Network::parse(&r.destination)?, r)))
        .collect::<io::Result<Vec<_>>>()?;
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
    Ok(result)
}

pub struct Service {
    root: PathBuf,
    busy: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl Service {
    pub fn new(state: &Path, stopping: Arc<AtomicBool>) -> io::Result<Self> {
        let root = state.join("routing");
        match std::fs::symlink_metadata(&root) {
            Ok(_) => secure_directory(&root, 0o700, 0o077)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(Self {
            root,
            busy: Arc::new(AtomicBool::new(false)),
            stopping,
            worker: None,
        })
    }
    pub fn busy(&self) -> bool {
        self.busy.load(Ordering::Relaxed)
    }
    pub fn reap(&mut self) {
        if self.worker.as_ref().is_some_and(|w| w.is_finished()) {
            let _ = self.worker.take().unwrap().join();
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
                json!({"data":{"desired_revision":store.config().revision,"busy":self.busy(),"recovery_required":optional::<Journal>(&self.root.join("journal.json"))?.as_ref().is_some_and(pending) && !self.busy(),"last_observation":saved}}),
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
        let proxy = match working {
            Some(w) => w.proxy,
            None => Proxy {
                port: TcpListener::bind("127.0.0.1:0")?.local_addr()?.port(),
                user: random_id()?,
                password: random_id()?,
            },
        };
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
            "capabilities":"conditional_on_runtime_probes","unmatched":"direct","unverified":"blocked","sessions_may_interrupt":true}),
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
    let previous: Option<Working> = optional(&root.join("working.json"))?;
    if let Some(w) = &previous
        && w.plan_id == plan.id
    {
        verify(
            &client,
            &w.snapshot,
            &w.config,
            &w.proxy,
            &w.matrix,
            &plan.ingress,
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
        let matrix = crate::probe::check(&client, &input.config, &journal.plan.proxy, None)?;
        let final_snapshot = render(
            &input,
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
            &input.config,
            &journal.plan.proxy,
            &matrix,
            &journal.plan.ingress,
        )?;
        let working = Working {
            plan_id: journal.plan.id.clone(),
            config: input.config.clone(),
            snapshot: final_snapshot.clone(),
            proxy: journal.plan.proxy.clone(),
            matrix,
        };
        let report = observation(
            &working.plan_id,
            &working.config,
            &working.snapshot,
            &working.matrix,
        );
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
) -> io::Result<()> {
    if client.status()?["running"] != true {
        return Err(io::Error::other("Xray is not running after apply"));
    }
    if client.read()? != *snapshot {
        return Err(invalid("observed panel drift during verification"));
    }
    wait_routes(client, config, matrix, ingress)?;
    crate::probe::check(client, config, proxy, Some(matrix))?;
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
        let network = Network::parse(&rule.destination)?;
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
        match verify_routes(client, config, matrix, ingress) {
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
    let total = matrix.len() * 4;
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
    let runtime_verified = if let Some(previous) = &journal.previous {
        verify(
            client,
            &journal.plan.base,
            &previous.config,
            &previous.proxy,
            &previous.matrix,
            &journal.plan.ingress,
        )
        .is_ok()
    } else {
        false
    };
    if let Some(previous) = &journal.previous {
        private_write(&root.join("working.json"), previous)?;
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
        "saved":"restored","running":if runtime_verified{"verified_previous"}else{"unverified"},"mismatch":true});
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
                                    g.id == c.group_id && g.primary.as_deref() == Some(&c.id)
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
