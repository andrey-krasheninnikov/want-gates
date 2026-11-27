use super::{Plan, Working, eligibility};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize)]
struct Change<'a> {
    kind: &'static str,
    id: &'a str,
    before: Option<Vec<String>>,
    after: Option<Vec<String>>,
    notes: Vec<&'static str>,
}

fn changes<'a, T>(
    kind: &'static str,
    before: &'a [T],
    after: &'a [T],
    key: impl Fn(&T) -> (&str, u64),
    describe: impl Fn(&T) -> Vec<String>,
    notes: impl Fn(&T, &T) -> Vec<&'static str>,
) -> Vec<Change<'a>> {
    let before: BTreeMap<_, _> = before.iter().map(|item| (key(item).0, item)).collect();
    let after: BTreeMap<_, _> = after.iter().map(|item| (key(item).0, item)).collect();
    let ids: BTreeSet<_> = before.keys().chain(after.keys()).copied().collect();
    ids.into_iter()
        .filter_map(|id| {
            let previous = before.get(id).copied();
            let proposed = after.get(id).copied();
            if previous
                .zip(proposed)
                .is_some_and(|(previous, proposed)| key(previous).1 == key(proposed).1)
            {
                return None;
            }
            Some(Change {
                kind,
                id,
                before: previous.map(&describe),
                after: proposed.map(&describe),
                notes: previous
                    .zip(proposed)
                    .map_or_else(Vec::new, |(old, new)| notes(old, new)),
            })
        })
        .collect()
}

pub(super) fn summary(plan: &Plan, working: Option<&Working>) -> Value {
    let before = working.map(|working| &working.config);
    let after = &plan.input.config;
    let mut changeset = changes(
        "rule",
        before.map_or(&[], |config| &config.rules),
        &after.rules,
        |rule| (&rule.id, rule.revision),
        |rule| {
            vec![
                rule.destination.clone(),
                format!("Company group {}", rule.group_id),
            ]
        },
        |_, _| Vec::new(),
    );
    changeset.extend(changes(
        "group",
        before.map_or(&[], |config| &config.groups),
        &after.groups,
        |group| (&group.id, group.revision),
        |group| {
            let mut details = vec![
                group.name.clone(),
                format!("Primary: {}", group.primary.as_deref().unwrap_or("none")),
                format!(
                    "Reserves in order: {}",
                    if group.fallbacks.is_empty() {
                        "none".to_owned()
                    } else {
                        group.fallbacks.join(", ")
                    }
                ),
            ];
            if let Some(check) = &group.healthcheck {
                details.push(format!(
                    "Healthcheck {} every {} s with a {} s timeout",
                    check.target, check.interval_seconds, check.timeout_seconds,
                ));
                details.push(format!(
                    "{} failures to switch, {} successes to recover. Required: {}",
                    check.failure_threshold,
                    check.recovery_threshold,
                    check.required_capabilities.join(", "),
                ));
                if url::Url::parse(&check.target)
                    .is_ok_and(|target| matches!(target.scheme(), "http" | "https"))
                {
                    details.push(format!(
                        "Expected HTTP status: {}",
                        check.expected_status.unwrap_or(200)
                    ));
                }
            } else {
                details.push("No automatic healthcheck".to_owned());
            }
            details
        },
        |old, new| {
            let old_check = old.healthcheck.as_ref();
            let new_check = new.healthcheck.as_ref();
            [
                (
                    old.probes != new.probes,
                    "Transport or DNS verification probes changed",
                ),
                (
                    old_check.and_then(|check| check.ca_pem.as_ref())
                        != new_check.and_then(|check| check.ca_pem.as_ref()),
                    "Healthcheck trust certificate changed",
                ),
                (
                    old_check.map(|check| (&check.send_hex, &check.expect_hex))
                        != new_check.map(|check| (&check.send_hex, &check.expect_hex))
                        && old_check
                            .into_iter()
                            .chain(new_check)
                            .any(|check| check.expect_hex.is_some()),
                    "Healthcheck TCP exchange changed",
                ),
            ]
            .into_iter()
            .filter_map(|(changed, label)| changed.then_some(label))
            .collect()
        },
    ));
    changeset.extend(changes(
        "connection",
        before.map_or(&[], |config| &config.connections),
        &after.connections,
        |connection| (&connection.id, connection.revision),
        |connection| {
            vec![
                connection.name.clone(),
                connection.protocol.clone(),
                format!("Company group {}", connection.group_id),
                format!("DNS: {}", connection.dns.as_deref().unwrap_or("default")),
                format!(
                    "Allowed transport: {}",
                    connection.allowed_capabilities.join(", ")
                ),
            ]
        },
        |old, new| {
            if old.profile_ref != new.profile_ref {
                vec!["Connection profile replaced"]
            } else {
                Vec::new()
            }
        },
    ));
    json!({
        "plan_id": plan.id,
        "desired_revision": after.revision,
        "ingress": plan.ingress,
        "rules": after.rules,
        "eligibility": eligibility(after),
        "changes": changeset,
        "base_revision": before.map(|config| config.revision),
        "prepared_connection_count": after.connections.len(),
        "unmatched": "direct",
        "unverified": "blocked",
        "sessions_may_interrupt": true,
    })
}
