use crate::invalid;
use crate::store::MAX_PROFILE;
use percent_encoding::percent_decode_str;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use url::Url;

pub fn parse(input: &str) -> io::Result<Value> {
    if input.len() > MAX_PROFILE {
        return Err(invalid("profile exceeds 1 MiB"));
    }
    let input = input.trim();
    let profile = if input.starts_with("vless://") {
        from_uri(input)?
    } else {
        strict_json(input)?
    };
    validate(&profile)?;
    Ok(profile)
}

// Reject duplicate JSON keys instead of silently replacing protocol settings.
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON value")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut map = Map::new();
                while let Some((key, Strict(value))) = a.next_entry::<String, Strict>()? {
                    if map.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate key"));
                    }
                }
                Ok(Strict(Value::Object(map)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(value)) = a.next_element()? {
                    values.push(value);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
        }
        d.deserialize_any(JsonVisitor)
    }
}
pub fn strict_json(input: &str) -> io::Result<Value> {
    serde_json::from_str::<Strict>(input)
        .map(|v| v.0)
        .map_err(|_| invalid("profile must be valid JSON without duplicate keys, or a VLESS URI"))
}

fn nonempty(value: &Value, message: &str) -> io::Result<()> {
    if value
        .as_str()
        .is_none_or(|s| s.trim().is_empty() || s.chars().any(char::is_control))
    {
        return Err(invalid(message));
    }
    Ok(())
}

pub fn validate(profile: &Value) -> io::Result<()> {
    if !profile.is_object() || profile["protocol"] != "vless" {
        return Err(invalid(
            "profile must be one Xray outbound with protocol vless",
        ));
    }
    let settings = &profile["settings"];
    if !settings.is_object() {
        return Err(invalid("VLESS settings object is required"));
    }
    let (endpoint, user) = if settings.get("address").is_some() {
        if settings.get("vnext").is_some() {
            return Err(invalid("use either flat VLESS settings or vnext, not both"));
        }
        (settings, settings)
    } else {
        let endpoints = settings["vnext"]
            .as_array()
            .filter(|v| v.len() == 1)
            .ok_or_else(|| invalid("vnext requires exactly one endpoint"))?;
        let users = endpoints[0]["users"]
            .as_array()
            .filter(|v| v.len() == 1)
            .ok_or_else(|| invalid("VLESS endpoint requires exactly one user"))?;
        (&endpoints[0], &users[0])
    };
    nonempty(&endpoint["address"], "VLESS address is required")?;
    if endpoint["port"]
        .as_u64()
        .is_none_or(|p| !(1..=65535).contains(&p))
    {
        return Err(invalid("VLESS port must be an integer from 1 to 65535"));
    }
    nonempty(&user["id"], "VLESS user ID is required")?;
    nonempty(
        &user["encryption"],
        "VLESS encryption must be explicit and nonempty",
    )?;
    for key in ["flow", "email"] {
        if user.get(key).is_some() && !user[key].is_string() {
            return Err(invalid("VLESS user optional fields have invalid types"));
        }
    }
    if user.get("level").is_some() && user["level"].as_u64().is_none_or(|n| n > u32::MAX as u64) {
        return Err(invalid("VLESS level must be a nonnegative 32-bit integer"));
    }
    if let Some(stream) = profile.get("streamSettings") {
        if !stream.is_object() {
            return Err(invalid("streamSettings must be an object"));
        }
        for key in ["method", "network", "security"] {
            if stream.get(key).is_some() {
                nonempty(&stream[key], "transport names must be nonempty strings")?;
            }
        }
        for (key, value) in stream.as_object().unwrap() {
            if (key.ends_with("Settings") || key == "sockopt" || key == "finalmask")
                && !value.is_object()
            {
                return Err(invalid("transport settings must be objects"));
            }
        }
    }
    for key in ["mux", "proxySettings"] {
        if profile.get(key).is_some() && !profile[key].is_object() {
            return Err(invalid("optional outbound settings must be objects"));
        }
    }
    Ok(())
}

fn decode(value: &str) -> io::Result<String> {
    let bytes = value.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'%'
            && (i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit())
        {
            return Err(invalid("invalid percent encoding in VLESS URI"));
        }
    }
    percent_decode_str(value)
        .decode_utf8()
        .map(|v| v.into_owned())
        .map_err(|_| invalid("VLESS URI must contain valid UTF-8"))
}

fn from_uri(input: &str) -> io::Result<Value> {
    if input.chars().any(char::is_whitespace) {
        return Err(invalid("VLESS URI must be one unbroken link"));
    }
    let url = Url::parse(input).map_err(|_| invalid("invalid VLESS URI"))?;
    if url.password().is_some() || !url.path().is_empty() {
        return Err(invalid("VLESS URI authority or path is invalid"));
    }
    let id = decode(url.username())?;
    let host = url
        .host_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("VLESS URI host is required"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = url
        .port()
        .filter(|p| *p != 0)
        .ok_or_else(|| invalid("VLESS URI port is required"))?;
    if let Some(fragment) = url.fragment() {
        decode(fragment)?;
    }
    let mut query = BTreeMap::new();
    let allowed = [
        "type",
        "encryption",
        "flow",
        "security",
        "path",
        "host",
        "mtu",
        "tti",
        "serviceName",
        "mode",
        "authority",
        "extra",
        "fm",
        "fp",
        "sni",
        "alpn",
        "ech",
        "pcs",
        "vcn",
        "pbk",
        "sid",
        "pqv",
        "spx",
        "seed",
        "headerType",
    ];
    if let Some(raw) = url.query() {
        for item in raw.split('&') {
            let (key, value) = item
                .split_once('=')
                .ok_or_else(|| invalid("VLESS query parameters need values"))?;
            let key = decode(key)?;
            let value = decode(value)?;
            if !allowed.contains(&key.as_str()) {
                return Err(invalid(
                    "unsupported VLESS URI parameter; use outbound JSON to preserve extended settings",
                ));
            }
            if query.insert(key, value).is_some() {
                return Err(invalid("duplicate VLESS URI parameter"));
            }
        }
    }
    let get = |key: &str, default: &str| {
        query
            .get(key)
            .map(String::as_str)
            .unwrap_or(default)
            .to_owned()
    };
    let network = get("type", "tcp");
    let security = get("security", "none");
    let mut stream = json!({"network":network,"security":security});
    let mut used = vec!["type", "encryption", "flow", "security"];
    let transport_key = match network.as_str() {
        "tcp" | "raw" => Some("rawSettings"),
        "kcp" | "mkcp" => Some("kcpSettings"),
        "ws" | "websocket" => Some("wsSettings"),
        "grpc" => Some("grpcSettings"),
        "xhttp" | "splithttp" => Some("xhttpSettings"),
        "httpupgrade" => Some("httpupgradeSettings"),
        _ => {
            return Err(invalid(
                "unsupported VLESS URI transport for Xray 26.9.9; use outbound JSON",
            ));
        }
    }
    .unwrap();
    let mut transport = json!({});
    match network.as_str() {
        "ws" | "websocket" | "xhttp" | "splithttp" | "httpupgrade" => {
            transport["path"] = json!(get("path", "/"));
            used.push("path");
            if let Some(host) = query.get("host") {
                if network == "ws" || network == "websocket" {
                    transport["headers"] = json!({"Host":host});
                } else {
                    transport["host"] = json!(host);
                }
                used.push("host");
            }
            if network == "xhttp" || network == "splithttp" {
                for key in ["mode", "extra"] {
                    if let Some(value) = query.get(key) {
                        transport[key] = if key == "extra" {
                            let v = strict_json(value)?;
                            if !v.is_object() {
                                return Err(invalid("XHTTP extra must be an object"));
                            }
                            v
                        } else {
                            json!(value)
                        };
                        used.push(key);
                    }
                }
            }
        }
        "grpc" => {
            for key in ["serviceName", "authority"] {
                if let Some(v) = query.get(key) {
                    transport[key] = json!(v);
                    used.push(key);
                }
            }
            if let Some(mode) = query.get("mode") {
                transport["multiMode"] = json!(match mode.as_str() {
                    "gun" => false,
                    "multi" => true,
                    _ => return Err(invalid("unsupported gRPC URI mode; use outbound JSON")),
                });
                used.push("mode");
            }
        }
        "kcp" | "mkcp" => {
            for key in ["mtu", "tti"] {
                if let Some(value) = query.get(key) {
                    transport[key] = json!(
                        value
                            .parse::<u32>()
                            .map_err(|_| invalid("mKCP numeric parameter is invalid"))?
                    );
                    used.push(key);
                }
            }
            if let Some(value) = query.get("seed") {
                transport["seed"] = json!(value);
                used.push("seed");
            }
            if let Some(value) = query.get("headerType") {
                transport["header"] = json!({"type":value});
                used.push("headerType");
            }
        }
        _ => {
            if let Some(header) = query.get("headerType") {
                if header != "none" {
                    return Err(invalid("RAW header extensions require outbound JSON"));
                }
                used.push("headerType");
            }
        }
    }
    stream[transport_key] = transport;
    if security == "tls" || security == "reality" {
        let mut tls = json!({"serverName":get("sni",host),"fingerprint":get("fp","chrome")});
        used.extend(["sni", "fp"]);
        let mappings: &[(&str, &str)] = if security == "tls" {
            &[
                ("alpn", "alpn"),
                ("ech", "echConfigList"),
                ("pcs", "pinnedPeerCertSha256"),
                ("vcn", "verifyPeerCertByName"),
            ]
        } else {
            &[
                ("pbk", "password"),
                ("sid", "shortId"),
                ("pqv", "mldsa65Verify"),
                ("spx", "spiderX"),
            ]
        };
        for (key, destination) in mappings {
            if let Some(value) = query.get(*key) {
                tls[*destination] = if *key == "alpn" {
                    json!(value.split(',').collect::<Vec<_>>())
                } else {
                    json!(value)
                };
                used.push(key);
            }
        }
        stream[if security == "tls" {
            "tlsSettings"
        } else {
            "realitySettings"
        }] = tls;
    } else if security != "none" {
        return Err(invalid("unsupported VLESS transport security"));
    }
    if let Some(fm) = query.get("fm") {
        let value = strict_json(fm)?;
        if !value.is_object() {
            return Err(invalid("finalmask must be an object"));
        }
        stream["finalmask"] = value;
        used.push("fm");
    }
    if query.keys().any(|key| !used.contains(&key.as_str())) {
        return Err(invalid(
            "VLESS URI parameter does not apply to its transport or security; use outbound JSON",
        ));
    }
    let profile = json!({"protocol":"vless","settings":{"address":host,"port":port,"id":id,
        "encryption":get("encryption","none"),"flow":get("flow","")},"streamSettings":stream});
    Ok(profile)
}
