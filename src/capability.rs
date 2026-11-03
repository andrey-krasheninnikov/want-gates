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
    permits(&connection.allowed_capabilities, capability)
        && !(connection.protocol == "forti" && capability.ends_with("_ipv6"))
}
pub fn observations(
    connection: &crate::store::Connection,
    results: Option<&BTreeMap<String, String>>,
    stale: bool,
) -> Value {
    let mut output = serde_json::Map::new();
    for capability in ALL {
        let reason = if connection.protocol == "forti" && capability.ends_with("_ipv6") {
            "protocol_limit"
        } else if !permits(&connection.allowed_capabilities, capability) {
            "configured_limit"
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

pub fn observation(reason: &str) -> Value {
    let state = match reason {
        "configured_limit" | "protocol_limit" => "unsupported",
        "inputs_changed" => "stale",
        "verified" => "verified",
        "probe_missing" | "not_checked" | "not_rechecked" | "primary_missing" => "unverified",
        _ => "unavailable",
    };
    let (reason, detail) = reason
        .strip_prefix("probe_failed: ")
        .map_or((reason, None), |detail| ("probe_failed", Some(detail)));
    json!({"state":state,"reason":reason,"detail":detail})
}
