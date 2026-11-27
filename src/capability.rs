use crate::invalid;
use serde_json::{Value, json};
use std::{collections::BTreeMap, io};

pub const ALL: [&str; 4] = ["tcp_ipv4", "udp_ipv4", "tcp_ipv6", "udp_ipv6"];
pub fn defaults() -> Vec<String> {
    ALL.iter().map(|s| (*s).to_owned()).collect()
}
pub fn validate(values: &[String]) -> io::Result<()> {
    if values.iter().any(|v| !ALL.contains(&v.as_str()))
        || values
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != values.len()
    {
        return Err(invalid(
            "capabilities require distinct tcp_ipv4, udp_ipv4, tcp_ipv6 or udp_ipv6 values",
        ));
    }
    Ok(())
}
pub fn parse(value: &str) -> io::Result<Vec<String>> {
    let values = match value {
        "all" => defaults(),
        "none" => Vec::new(),
        _ => value.split(',').map(str::to_owned).collect(),
    };
    validate(&values)?;
    Ok(values)
}
pub fn permits(values: &[String], capability: &str) -> bool {
    values.iter().any(|s| s == capability)
}
pub fn permits_connection(connection: &crate::store::Connection, capability: &str) -> bool {
    connection_limit(connection, capability).is_none()
}
pub fn connection_limit(
    connection: &crate::store::Connection,
    capability: &str,
) -> Option<&'static str> {
    if connection.protocol == "forti" && capability.ends_with("_ipv6") {
        Some("protocol_limit")
    } else if !permits(&connection.allowed_capabilities, capability) {
        Some("configured_limit")
    } else {
        None
    }
}
pub fn observations(
    connection: &crate::store::Connection,
    results: Option<&BTreeMap<String, String>>,
    stale: bool,
) -> Value {
    let mut output = serde_json::Map::new();
    for capability in ALL {
        let reason = if let Some(reason) = connection_limit(connection, capability) {
            reason
        } else if stale {
            "inputs_changed"
        } else {
            results
                .and_then(|r| r.get(capability))
                .map(String::as_str)
                .unwrap_or("not_checked")
        };
        output.insert(capability.to_owned(), observation(reason));
    }
    Value::Object(output)
}

pub fn public_reason(reason: &str) -> &str {
    match reason {
        "candidate" => "verification_required",
        reason if reason.starts_with("probe_failed:") => "probe_failed",
        "verified"
        | "configured_limit"
        | "protocol_limit"
        | "probe_missing"
        | "probe_failed"
        | "probe_timed_out"
        | "no_eligible_connection"
        | "primary_missing"
        | "not_checked"
        | "not_rechecked"
        | "inputs_changed"
        | "awaiting_probe"
        | "healthcheck_pending"
        | "dns_missing"
        | "dns_failed"
        | "dns_capability_missing"
        | "dns_transport_unverified"
        | "native_authentication_required"
        | "native_unavailable"
        | "native_runtime_unavailable"
        | "native_session_requires_verification"
        | "netbird_confirming_routes"
        | "target_failed"
        | "target_status_failed"
        | "target_response_mismatch"
        | "target_response_too_large"
        | "capability_missing"
        | "tls_failed"
        | "authenticated"
        | "authenticating"
        | "credentials_required"
        | "challenge_required"
        | "browser_required"
        | "configured"
        | "unavailable"
        | "stopped"
        | "expired"
        | "failed"
        | "unknown" => reason,
        _ => "unknown",
    }
}

pub fn observation(reason: &str) -> Value {
    let reason = public_reason(reason);
    let state = match reason {
        "configured_limit" | "protocol_limit" => "unsupported",
        "inputs_changed" => "stale",
        "verified" => "verified",
        "probe_missing" | "not_checked" | "not_rechecked" | "primary_missing" => "unverified",
        _ => "unavailable",
    };
    json!({"state":state,"reason":reason,"detail":null})
}
