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
    let mut profile = if input.trim_start().starts_with('{') {
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
    validate_and_normalize(&mut profile)?;
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

fn validate_and_normalize(profile: &mut Profile) -> io::Result<()> {
    if profile.options.len() > 64 || profile.inline.keys().any(|k| !ASSETS.contains(&k.as_str())) {
        return Err(invalid("unsupported Forti profile structure"));
    }
    let mut seen = BTreeMap::new();
    for option in &mut profile.options {
        let [key, stored_value] = option.as_mut_slice() else {
            return Err(invalid("invalid Forti option value"));
        };
        let (key, value) = (key.as_str(), stored_value.as_str());
        if [key, value]
            .into_iter()
            .any(|v| v.is_empty() || v.len() > 4096 || v.chars().any(char::is_control))
        {
            return Err(invalid("invalid Forti option value"));
        }
        let count = seen.entry(key).or_insert(0);
        *count += 1;
        if *count > 1 && key != "trusted-cert" {
            return Err(invalid("duplicate Forti option"));
        }
        let valid = match key {
            "host" if value.parse::<std::net::Ipv4Addr>().is_ok() => true,
            "host" | "sni" => match crate::policy::domain_name(value) {
                Ok(name) => {
                    *stored_value = name;
                    true
                }
                Err(_) => false,
            },
            "port" => value
                .parse::<u16>()
                .is_ok_and(|v| v != 0 && v.to_string() == value),
            "realm" => value.len() <= 63 && value.trim() == value,
            "trusted-cert" => {
                *count <= 16 && value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
            }
            "otp-prompt" if value.len() <= 255 => {
                *stored_value = value.trim_matches(' ').to_owned();
                true
            }
            "otp-delay" => match value.parse::<u8>() {
                Ok(delay @ 0..=60) => {
                    *stored_value = delay.to_string();
                    true
                }
                _ => false,
            },
            "otp-prompt" => false,
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
    profile.options.retain(|option| !option[1].is_empty());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_forti_otp_options_on_import_and_restore() {
        let saved = json!({
            "protocol": "forti",
            "options": [["host", "vpn.example.test"], ["otp-delay", "08"], ["otp-prompt", " Entrez "]],
            "inline": {}
        });
        let restored = decoded_profile(&saved).unwrap();
        assert_eq!(option(&restored, "otp-delay"), Some("8"));
        assert_eq!(option(&restored, "otp-prompt"), Some("Entrez"));
        let raw = parse("host = vpn.example.test\notp-delay = 08\notp-prompt = Entrez\n").unwrap();
        assert_eq!(parse(&saved.to_string()).unwrap(), raw);
    }

    #[test]
    fn canonicalizes_forti_dns_host_and_sni() {
        let saved = json!({
            "protocol": "forti",
            "options": [["host", "büro.example"], ["sni", "büro.example"]],
            "inline": {}
        });
        let restored = decoded_profile(&saved).unwrap();
        assert_eq!(option(&restored, "host"), Some("xn--bro-hoa.example"));
        assert_eq!(option(&restored, "sni"), Some("xn--bro-hoa.example"));
        let literal = parse("host = 192.0.2.1\n").unwrap();
        assert_eq!(literal["options"][0][1], "192.0.2.1");
    }

    #[test]
    fn omits_an_empty_forti_otp_prompt_from_saved_profiles() {
        let saved = json!({
            "protocol": "forti",
            "options": [["host", "vpn.example.test"], ["otp-prompt", "  "]],
            "inline": {}
        });
        assert_eq!(
            option(&decoded_profile(&saved).unwrap(), "otp-prompt"),
            None
        );
    }
}
