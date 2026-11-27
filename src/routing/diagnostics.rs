use super::{
    Journal, Matrix, Service, Working, allowed, initial_matrix, network_winner, optional, pending,
};
use crate::invalid;
use crate::policy::{Network, Rule, domain_name};
use crate::store::{self, Config};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    io,
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const LOG_CAPACITY: usize = 128;

#[derive(Clone, Default)]
pub(super) struct Events(Arc<Mutex<VecDeque<Value>>>);

impl Events {
    pub(super) fn record(&self, operation: &str, outcome: &str) {
        let mut entries = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if entries.len() == LOG_CAPACITY {
            entries.pop_front();
        }
        entries.push_back(json!({
            "observed_at":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            "operation":operation,"outcome":outcome
        }));
    }

    pub(super) fn list(&self, limit: Option<&Value>) -> io::Result<Value> {
        let limit = limit
            .map_or(Some(20), Value::as_u64)
            .filter(|n| (1..=LOG_CAPACITY as u64).contains(n))
            .ok_or_else(|| invalid("log limit must be an integer from 1 to 128"))?;
        let entries = self.0.lock().unwrap_or_else(|error| error.into_inner());
        Ok(json!({"data":entries.iter().rev().take(limit as usize).collect::<Vec<_>>() }))
    }
}

pub(super) fn event_outcome(result: &io::Result<Value>) -> &'static str {
    let Ok(data) = result else {
        return "failed";
    };
    match data["state"].as_str() {
        Some("blocked") => "blocked",
        Some("partial") => "partial",
        Some("restored") => "restored",
        Some("restored_runtime_unverified") => "restored_runtime_unverified",
        _ if data["probe"]["state"] == "failed" => "failed",
        _ if data["probe"]["state"] == "skipped" => "skipped",
        _ => "completed",
    }
}

pub(super) fn health_problem(error: &str) -> &'static str {
    if error.contains("drift") {
        "panel_drift"
    } else if error.contains("identity changed") {
        "panel_identity_changed"
    } else if error.contains("recover") {
        "recovery_required"
    } else {
        "healthcheck_failed"
    }
}

enum Destination {
    Ip(IpAddr),
    Host(String),
}

impl Destination {
    fn parse(value: &str, capability: &str) -> io::Result<Self> {
        if let Ok(ip) = value.parse::<IpAddr>() {
            Network::parse(value)?;
            if capability.ends_with("ipv4") != ip.is_ipv4() {
                return Err(invalid(
                    "capability does not match the destination IP family",
                ));
            }
            return Ok(Self::Ip(ip));
        }
        Ok(Self::Host(domain_name(value)?))
    }

    fn rule<'a>(&self, config: &'a Config) -> Option<&'a Rule> {
        match self {
            Self::Ip(ip) => network_winner(config, *ip),
            Self::Host(name) => crate::domain::winner(config, name),
        }
    }

    fn report(
        &self,
        config: &Config,
        matrix: &Matrix,
        capability: &str,
        working: Option<&Working>,
    ) -> Value {
        let hostname = matches!(self, Self::Host(_));
        let Some(rule) = self.rule(config) else {
            return json!({"decision":"unmatched","reason":"no_rule","rule_id":null,"group_id":null,
                "connection":null,"candidates":[],"candidate_count":0,"dns":{"mode":if hostname{"panel_default"}else{"not_required"}}});
        };
        let group = config.groups.iter().find(|g| g.id == rule.group_id);
        let connection = group.and_then(|g| crate::domain::connection(config, g));
        let reasons = matrix.get(&rule.group_id);
        let traffic_allowed = allowed(matrix, &rule.group_id, capability);
        let dns_allowed =
            !hostname || group.is_some_and(|g| crate::domain::usable(config, g, matrix));
        let capability_reason = reasons
            .and_then(|row| row.get(capability))
            .map_or("primary_missing", |reason| {
                crate::capability::public_reason(reason)
            });
        let dns_reason = reasons
            .and_then(|row| row.get("dns"))
            .map_or("dns_missing", |reason| {
                crate::capability::public_reason(reason)
            });
        let reason = if traffic_allowed && !dns_allowed {
            dns_reason
        } else {
            capability_reason
        };
        let selected = connection.map(|c| c.id.as_str());
        let (candidates, candidate_count) = candidates(
            working.map_or(config, |w| &w.config),
            &rule.group_id,
            selected,
            capability,
            hostname,
            reason,
            working,
        );
        let resolver = connection
            .and_then(|c| c.dns.as_deref())
            .and_then(|value| crate::policy::Resolver::parse(value).ok());
        json!({
            "decision": if connection.is_some() && traffic_allowed && dns_allowed { "group" } else { "blocked" },
            "reason":reason,"rule_id":rule.id,"rule":rule.destination,
            "group_id":rule.group_id,"group_name":group.map(|g|&g.name),
            "connection":connection.map(|c|json!({"id":c.id,"name":c.name,"protocol":c.protocol})),
            "capability_reason":capability_reason,"candidates":candidates,"candidate_count":candidate_count,
            "dns":if hostname {
                json!({"mode":if dns_allowed{"connection"}else{"blocked"},"reason":dns_reason,
                    "resolver_capability":resolver.map(|r|r.capability())})
            } else {json!({"mode":"not_required"})}
        })
    }
}

fn candidates(
    config: &Config,
    group_id: &str,
    selected: Option<&str>,
    capability: &str,
    hostname: bool,
    selected_reason: &str,
    working: Option<&Working>,
) -> (Vec<Value>, usize) {
    const LIMIT: usize = 64;
    let Some(group) = config.groups.iter().find(|group| group.id == group_id) else {
        return (Vec::new(), 0);
    };
    let ordered = group.primary.iter().chain(&group.fallbacks);
    let count = ordered.clone().count();
    let candidates = ordered
        .enumerate()
        .filter(|(index, id)| *index < LIMIT || Some(id.as_str()) == selected)
        .filter_map(|(_, id)| config.connections.iter().find(|c| &c.id == id))
        .map(|connection| {
            let selected = selected == Some(connection.id.as_str());
            let history = working.and_then(|w| w.health.get(&connection.id));
            let reason = crate::capability::connection_limit(connection, capability)
                .or_else(|| {
                    working
                        .and_then(|w| crate::native::readiness(connection, &w.native_observations))
                })
                .unwrap_or_else(|| {
                    if selected {
                        selected_reason
                    } else if let Some(record) = history {
                        if !record.fresh {
                            "awaiting_probe"
                        } else if !record.available {
                            "unhealthy"
                        } else if record
                            .admitted
                            .get(capability)
                            .is_none_or(|v| v != "verified")
                        {
                            record
                                .results
                                .get(capability)
                                .map_or("not_checked", |reason| {
                                    crate::capability::public_reason(reason)
                                })
                        } else if hostname
                            && record.admitted.get("dns").is_none_or(|v| v != "verified")
                        {
                            record
                                .results
                                .get("dns")
                                .map_or("dns_transport_unverified", |reason| {
                                    crate::capability::public_reason(reason)
                                })
                        } else {
                            "lower_priority"
                        }
                    } else if working.is_none() {
                        "verification_required"
                    } else {
                        "not_selected"
                    }
                });
            let authentication = if crate::native::is_native(&connection.protocol) {
                working
                    .and_then(|w| w.native_observations.get(&connection.id))
                    .map_or("unknown", |observation| {
                        crate::capability::public_reason(&observation.authentication)
                    })
            } else if selected && selected_reason == "verified" {
                "traffic_verified"
            } else {
                "unverified"
            };
            json!({"id":connection.id,"name":connection.name,"protocol":connection.protocol,
                "role":if group.primary.as_ref()==Some(&connection.id){"primary"}else{"fallback"},
                "selected":selected,"reason":reason,"authentication":authentication,
                "allowed_capabilities":connection.allowed_capabilities,
                "health":history.map(|record|record.describe())})
        })
        .collect();
    (candidates, count)
}

impl Service {
    pub(super) fn diagnose(
        &mut self,
        request: &Value,
        config: &Config,
        stream: &std::os::unix::net::UnixStream,
    ) -> io::Result<Option<Value>> {
        let capability = store::text(&request["capability"])?;
        if !crate::capability::ALL.contains(&capability) {
            return Err(invalid(
                "capability must be tcp_ipv4, udp_ipv4, tcp_ipv6 or udp_ipv6",
            ));
        }
        let destination = Destination::parse(store::text(&request["destination"])?, capability)?;
        let probe = request.get("probe").map_or(Ok(false), |value| {
            value
                .as_bool()
                .ok_or_else(|| invalid("probe must be a boolean"))
        })?;
        let busy = self.busy();
        let working: Option<Working> = optional(&self.root.join("working.json"))?;
        let status: Value = optional(&self.root.join("status.json"))?.unwrap_or(Value::Null);
        let pending_recovery = optional::<Journal>(&self.root.join("journal.json"))?
            .as_ref()
            .is_some_and(pending);
        let runtime = if busy {
            "busy"
        } else if pending_recovery {
            "recovery_required"
        } else if let Some(working) = &working {
            if working.config.revision != config.revision {
                "pending_apply"
            } else if working.health_error.is_some()
                || status["mismatch"] == true
                || status["running_revision"].as_u64() != Some(working.config.revision)
            {
                "unverified"
            } else {
                "last_observed"
            }
        } else {
            "unapplied"
        };
        let desired = destination.report(config, &initial_matrix(config), capability, None);
        let last_observed = working.as_ref().map(|working| {
            destination.report(
                &working.effective_config(),
                &working.matrix,
                capability,
                Some(working),
            )
        });
        let connection = last_observed
            .as_ref()
            .filter(|report| report["decision"] == "group")
            .and_then(|report| report["connection"]["id"].as_str())
            .map(str::to_owned);
        let name = match destination {
            Destination::Ip(ip) => ip.to_string(),
            Destination::Host(host) => host,
        };
        let mut data = json!({
            "destination":name,"capability":capability,"mode":"synthetic",
            "desired_revision":config.revision,"runtime":runtime,
            "observed_revision":working.as_ref().map(|w|w.config.revision),
            "observed_at":status["observed_at"],"desired":desired,"last_observed":last_observed,
            "probe":{"state":"not_requested"}
        });
        if !probe {
            return Ok(Some(json!({"data":data})));
        }
        if let (Some(working), Some(connection), "last_observed") = (working, connection, runtime) {
            let root = self.root.clone();
            let stopping = self.stopping.clone();
            let native = self.native.clone();
            let xray = self.xray.clone();
            let capability = capability.to_owned();
            return self.launch(stream, "routing.diagnose".into(), move || {
                data["probe"] = run_probe(
                    &root,
                    &working,
                    &connection,
                    &capability,
                    stopping,
                    &native,
                    &xray,
                )
                .unwrap_or_else(|reason| json!({"state":"skipped","reason":reason}));
                Ok(data)
            });
        }
        let reason = if runtime == "last_observed" {
            data["last_observed"]["reason"]
                .as_str()
                .unwrap_or("no_eligible_connection")
        } else {
            runtime
        };
        data["probe"] = json!({"state":"skipped","reason":reason});
        Ok(Some(json!({"data":data})))
    }
}

fn run_probe(
    root: &Path,
    working: &Working,
    id: &str,
    capability: &str,
    stopping: Arc<std::sync::atomic::AtomicBool>,
    native: &crate::native::Client,
    xray: &Path,
) -> Result<Value, &'static str> {
    let config = working.effective_config();
    let connection = config
        .connections
        .iter()
        .find(|c| c.id == id)
        .ok_or("connection_unavailable")?;
    let group = config
        .groups
        .iter()
        .find(|g| g.id == connection.group_id)
        .ok_or("group_unavailable")?;
    let use_health = group.healthcheck.as_ref().is_some_and(|check| {
        check
            .required_capabilities
            .iter()
            .any(|value| value == capability)
    });
    if !use_health && !super::probe_configured(group, capability) {
        return Ok(json!({"state":"skipped","reason":"probe_missing"}));
    }

    let settings: crate::panel::Settings =
        super::read(&root.join("panel.json")).map_err(|_| "panel_configuration_unavailable")?;
    if working.panel_digest != super::digest(&settings).ok() {
        return Err("panel_identity_changed");
    }
    let client = crate::panel::Client::new(settings, stopping)
        .map_err(|_| "panel_configuration_unavailable")?;
    let status = client.running().map_err(|_| "panel_unavailable")?;
    let outbound = LiveOutbound::new(xray, &working.snapshot.template, connection)?;
    outbound.verify()?;
    if crate::native::is_native(&connection.protocol) {
        let observations =
            crate::native::observe(native, &working.native).map_err(|_| "native_unavailable")?;
        if let Some(reason) = crate::native::readiness(connection, &observations) {
            return Err(reason);
        }
        if observations
            .get(id)
            .is_some_and(|now| now.reason == crate::native::NETBIRD_CONFIRMING_ROUTES)
        {
            return Err(crate::native::NETBIRD_CONFIRMING_ROUTES);
        }
        if !working
            .native_observations
            .get(id)
            .zip(observations.get(id))
            .is_some_and(|(before, now)| {
                now.admitted && before.session == now.session && before.dns == now.dns
            })
        {
            return Err("native_context_changed");
        }
        super::check_native_xray(native, &status, json!([]))
            .map_err(|_| "native_stack_unverified")?;
    }

    let (source, result) = if use_health {
        (
            "configured_health_target",
            crate::probe::health(&client, &config, connection, &working.proxy),
        )
    } else {
        (
            "configured_connection_probes",
            crate::probe::connection(&client, &config, connection, &working.proxy),
        )
    };
    outbound.verify()?;
    client.running().map_err(|_| "panel_unavailable")?;
    let Ok(result) = result else {
        return Ok(json!({"state":"failed","reason":"probe_failed"}));
    };
    let key = if use_health { "health" } else { capability };
    let reason = result.get(key).map_or("not_checked", |reason| {
        crate::capability::public_reason(reason)
    });
    let results: std::collections::BTreeMap<_, _> = result
        .iter()
        .map(|(key, value)| (key, crate::capability::public_reason(value)))
        .collect();
    Ok(
        json!({"state":if reason=="verified"{"passed"}else{"failed"},
        "reason":reason,"source":source,"connection_id":id,"results":results}),
    )
}

struct LiveOutbound {
    #[cfg(target_os = "linux")]
    binary: std::path::PathBuf,
    #[cfg(target_os = "linux")]
    address: String,
    #[cfg(target_os = "linux")]
    expected: Value,
}

impl LiveOutbound {
    fn new(
        binary: &Path,
        template: &Value,
        connection: &crate::store::Connection,
    ) -> Result<Self, &'static str> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (binary, template, connection);
            Err("probe_context_unavailable")
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::{fd::OwnedFd, unix::net::UnixStream};
            use std::process::Stdio;
            use std::time::Duration;

            let unavailable = "probe_context_unavailable";
            let binary = crate::native_runtime::executable(binary).map_err(|_| unavailable)?;
            let program = binary.to_str().ok_or(unavailable)?;
            let port = template["inbounds"]
                .as_array()
                .and_then(|inbounds| inbounds.iter().find(|inbound| inbound["tag"] == "api"))
                .and_then(|inbound| inbound["port"].as_u64())
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .ok_or(unavailable)?;
            let tag = crate::native::diagnostic_tag(connection);
            let outbound = template["outbounds"]
                .as_array()
                .and_then(|outbounds| outbounds.iter().find(|outbound| outbound["tag"] == tag))
                .ok_or(unavailable)?;
            // Keep the private outbound out of files and process arguments.
            let payload = json!({"outbounds":[outbound]});
            let (input, writer) = UnixStream::pair().map_err(|_| unavailable)?;
            writer
                .set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(|_| unavailable)?;
            let output = std::thread::scope(|scope| {
                let write = scope.spawn(move || serde_json::to_writer(writer, &payload));
                let output = crate::native_runtime::command_input(
                    program,
                    &["convert", "pb", "-d", "-t", "stdin:"],
                    Stdio::from(OwnedFd::from(input)),
                );
                write
                    .join()
                    .map_err(|_| unavailable)?
                    .map_err(|_| unavailable)?;
                output.map_err(|_| unavailable)
            })?;
            let expected = Self::json(&output)?["outbound"]
                .as_array()
                .and_then(|outbounds| outbounds.first())
                .filter(|outbound| outbound["tag"] == tag)
                .cloned()
                .ok_or(unavailable)?;
            Ok(Self {
                binary,
                address: format!("127.0.0.1:{port}"),
                expected,
            })
        }
    }

    #[cfg(target_os = "linux")]
    fn json(output: &str) -> Result<Value, &'static str> {
        // Xray can print a config-loading message before its JSON document.
        let start = if output.starts_with('{') {
            0
        } else {
            output.find("\n{").ok_or("probe_context_unavailable")? + 1
        };
        serde_json::from_str(&output[start..]).map_err(|_| "probe_context_unavailable")
    }

    fn verify(&self) -> Result<(), &'static str> {
        #[cfg(not(target_os = "linux"))]
        return Err("probe_context_unavailable");

        #[cfg(target_os = "linux")]
        {
            let unavailable = "probe_context_unavailable";
            let output = crate::native_runtime::command_input(
                self.binary.to_str().ok_or(unavailable)?,
                &["api", "lso", "-s", &self.address, "-t", "3"],
                std::process::Stdio::null(),
            )
            .map_err(|_| unavailable)?;
            let actual = Self::json(&output)?;
            let matches = actual["outbounds"]
                .as_array()
                .ok_or(unavailable)?
                .iter()
                .filter(|outbound| outbound["tag"] == self.expected["tag"]);
            if matches.eq(std::iter::once(&self.expected)) {
                Ok(())
            } else {
                Err("panel_drift")
            }
        }
    }
}
