use crate::openvpn::Profile;
use crate::{invalid, store::MAX_PROFILE};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io, path::Path};

const ASSETS: &[&str] = &["ca-file", "user-cert", "user-key"];

pub fn parse(input: &str) -> io::Result<Value> {
    bundle(input, None).and_then(|s| crate::profile::strict_json(&s))
}

pub fn bundle(input: &str, directory: Option<&Path>) -> io::Result<String> {
    if input.len() > MAX_PROFILE || input.contains('\0') {
        return Err(invalid("invalid or oversized Forti profile"));
    }
    let profile = if input.trim_start().starts_with('{') {
        let mut value = crate::profile::strict_json(input)?;
        if value.as_object_mut().and_then(|o| o.remove("protocol")) != Some(json!("forti")) {
            return Err(invalid("invalid Forti protocol"));
        }
        serde_json::from_value::<Profile>(value).map_err(|_| invalid("invalid Forti profile"))?
    } else {
        let mut profile = Profile {
            options: Vec::new(),
            inline: BTreeMap::new(),
        };
        for line in input
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
        {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| invalid("Forti options require key = value"))?;
            let (key, value) = (key.trim(), value.trim());
            if ASSETS.contains(&key) {
                if profile.inline.contains_key(key) {
                    return Err(invalid("duplicate Forti asset"));
                }
                let directory = directory
                    .ok_or_else(|| invalid("external Forti assets require a profile file"))?;
                let bytes = crate::openvpn::asset(directory, value)?;
                let data = String::from_utf8(bytes)
                    .map_err(|_| invalid("Forti PEM asset must be UTF-8"))?;
                profile.inline.insert(key.to_owned(), data);
            } else {
                profile.options.push(vec![key.to_owned(), value.to_owned()]);
            }
        }
        profile
    };
    validate(&profile)?;
    let mut value = serde_json::to_value(profile)?;
    value["protocol"] = json!("forti");
    let result = value.to_string();
    if result.len() > MAX_PROFILE {
        return Err(invalid("profile exceeds 1 MiB after packaging"));
    }
    Ok(result)
}

pub fn decoded_profile(value: &Value) -> io::Result<Profile> {
    let mut value = parse(&value.to_string())?;
    value.as_object_mut().unwrap().remove("protocol");
    serde_json::from_value(value).map_err(|_| invalid("invalid Forti profile"))
}

pub fn option<'a>(profile: &'a Profile, key: &str) -> Option<&'a str> {
    profile
        .options
        .iter()
        .find(|o| o[0] == key)
        .map(|o| o[1].as_str())
}

fn validate(profile: &Profile) -> io::Result<()> {
    if profile.options.len() > 64 || profile.inline.keys().any(|k| !ASSETS.contains(&k.as_str())) {
        return Err(invalid("unsupported Forti profile structure"));
    }
    let mut seen = BTreeMap::new();
    for option in &profile.options {
        if option.len() != 2
            || option
                .iter()
                .any(|v| v.is_empty() || v.len() > 4096 || v.chars().any(char::is_control))
        {
            return Err(invalid("invalid Forti option value"));
        }
        let (key, value) = (option[0].as_str(), option[1].as_str());
        let count = seen.entry(key).or_insert(0);
        *count += 1;
        if *count > 1 && key != "trusted-cert" {
            return Err(invalid("duplicate Forti option"));
        }
        let valid = match key {
            "host" => {
                value.parse::<std::net::Ipv4Addr>().is_ok()
                    || crate::policy::domain_name(value).is_ok()
            }
            "port" => value.parse::<u16>().is_ok_and(|v| v != 0),
            "realm" => value.len() <= 255 && !value.chars().any(char::is_whitespace),
            "trusted-cert" => {
                *count <= 16 && value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
            }
            "sni" => crate::policy::domain_name(value).is_ok(),
            "otp-prompt" => value.len() <= 255,
            "otp-delay" => value.parse::<u8>().is_ok_and(|v| v <= 60),
            "no-ftm-push" => matches!(value, "0" | "1"),
            "min-tls" => matches!(value, "1.2" | "1.3"),
            "set-dns" | "set-routes" | "pppd-use-peerdns" | "use-resolvconf" => {
                matches!(value, "0" | "1")
            }
            "persistent" => value == "0",
            "password" | "username" | "otp" | "cookie" | "pem-passphrase" => {
                return Err(invalid(
                    "Forti credentials belong in connection login, not the profile",
                ));
            }
            _ => {
                return Err(invalid(
                    "unsupported Forti option; hooks, plugins, external credentials and unsafe TLS settings are unavailable",
                ));
            }
        };
        if !valid {
            return Err(invalid("invalid or unsupported Forti option value"));
        }
    }
    if option(profile, "host").is_none() {
        return Err(invalid("Forti host is required"));
    }
    if profile.inline.contains_key("user-cert") != profile.inline.contains_key("user-key") {
        return Err(invalid(
            "Forti client certificate and key must be supplied together",
        ));
    }
    for (key, data) in &profile.inline {
        if data.len() > MAX_PROFILE
            || data.contains('\0')
            || !data.contains("-----BEGIN ")
            || !data.contains("-----END ")
            || data.lines().any(|l| l.trim_start().starts_with('<'))
        {
            return Err(invalid("invalid Forti PEM asset"));
        }
        if key != "user-key"
            && (!data.contains("-----BEGIN CERTIFICATE-----")
                || !data.contains("-----END CERTIFICATE-----"))
        {
            return Err(invalid("invalid Forti certificate asset"));
        }
        if key == "user-key" && !data.contains("PRIVATE KEY-----") {
            return Err(invalid("invalid Forti key asset"));
        }
    }
    Ok(())
}
