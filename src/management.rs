use crate::{API_VERSION, HELP, invalid, read_message, write_message};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

pub fn run(kind: &str, mut args: impl Iterator<Item = OsString>) -> io::Result<()> {
    let action = args
        .next()
        .ok_or_else(|| invalid("a management action is required; run wgates --help"))?;
    if action == "--help" || action == "-h" {
        print!("{HELP}");
        return Ok(());
    }
    let action = action.to_str().ok_or_else(|| invalid("invalid action"))?;
    let allowed: &[&str] = match (kind, action) {
        ("group", "create" | "update") => &["--name"],
        ("group", "list" | "show" | "delete") => &[],
        ("connection", "import") => &["--name", "--group", "--protocol", "--file"],
        ("connection", "update") => &["--name", "--group", "--file"],
        ("connection", "list") => &["--group", "--sort"],
        ("connection", "show" | "delete") => &[],
        _ => return Err(invalid("unsupported management action; run wgates --help")),
    };
    let id = if matches!(action, "show" | "update" | "delete") {
        Some(
            args.next()
                .ok_or_else(|| invalid("object ID is required"))?,
        )
    } else {
        None
    };
    let mut options = BTreeMap::new();
    let mut socket = PathBuf::from("/run/wgates/control.sock");
    while let Some(option) = args.next() {
        if option == "--help" || option == "-h" {
            print!("{HELP}");
            return Ok(());
        }
        let option = option
            .to_str()
            .ok_or_else(|| invalid("invalid option"))?
            .to_owned();
        if option != "--socket" && !allowed.contains(&option.as_str()) {
            return Err(invalid("unknown option; run wgates --help"));
        }
        let value = args
            .next()
            .ok_or_else(|| invalid("option requires a value"))?;
        if options.insert(option.clone(), value.clone()).is_some() {
            return Err(invalid("duplicate option"));
        }
        if option == "--socket" {
            socket = value.into();
        }
    }
    if !socket.is_absolute() {
        return Err(invalid("socket path must be absolute"));
    }
    let mut request = json!({"api_version":API_VERSION,"command":format!("{kind}.{action}")});
    if let Some(id) = id {
        request["id"] = json!(id.to_str().ok_or_else(|| invalid("invalid object ID"))?);
    }
    for (option, field) in [
        ("--name", "name"),
        ("--group", "group_id"),
        ("--protocol", "protocol"),
        ("--sort", "sort"),
    ] {
        if let Some(value) = options.get(option) {
            request[field] = json!(
                value
                    .to_str()
                    .ok_or_else(|| invalid("option must be valid UTF-8"))?
            );
        }
    }
    if action == "create" && request.get("name").is_none() {
        return Err(invalid("--name is required"));
    }
    if action == "import"
        && ["--name", "--group", "--protocol", "--file"]
            .iter()
            .any(|key| !options.contains_key(*key))
    {
        return Err(invalid(
            "import requires --name, --group, --protocol and --file",
        ));
    }
    if let Some(path) = options.get("--file") {
        let source: Box<dyn Read> = if path == "-" {
            Box::new(io::stdin())
        } else {
            Box::new(std::fs::File::open(path)?)
        };
        let mut bytes = Vec::new();
        source
            .take(crate::store::MAX_PROFILE as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > crate::store::MAX_PROFILE {
            return Err(invalid("profile exceeds 1 MiB"));
        }
        request["profile"] =
            json!(String::from_utf8(bytes).map_err(|_| invalid("profile must be valid UTF-8"))?);
    }
    if matches!(action, "update" | "delete") {
        let current = exchange(
            &socket,
            &json!({"api_version":API_VERSION,"command":format!("{kind}.show"),"id":request["id"]}),
        )?;
        request["expected_revision"] = current["data"]["revision"]
            .as_u64()
            .map(Value::from)
            .ok_or_else(|| invalid("invalid object revision in service response"))?;
    }
    let mut response = exchange(&socket, &request)?;
    if action == "list" {
        let mut all = response["data"]
            .as_array()
            .ok_or_else(|| invalid("invalid list response"))?
            .clone();
        let revision = response["list_revision"]
            .as_u64()
            .ok_or_else(|| invalid("invalid list revision"))?;
        let mut previous_offset = 0;
        while !response["next_offset"].is_null() {
            let offset = response["next_offset"]
                .as_u64()
                .filter(|n| *n > previous_offset)
                .ok_or_else(|| invalid("invalid list continuation"))?;
            previous_offset = offset;
            request["offset"] = json!(offset);
            request["list_revision"] = json!(revision);
            response = exchange(&socket, &request)?;
            if response["list_revision"].as_u64() != Some(revision) {
                return Err(invalid("configuration changed during listing; retry"));
            }
            all.extend(
                response["data"]
                    .as_array()
                    .ok_or_else(|| invalid("invalid list response"))?
                    .iter()
                    .cloned(),
            );
        }
        response = json!({"api_version":API_VERSION,"data":all});
    }
    println!("{response}");
    Ok(())
}

fn exchange(socket: &std::path::Path, request: &Value) -> io::Result<Value> {
    let mut stream = UnixStream::connect(socket).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot reach {}: {error}; start wgates.service and check socket access",
                socket.display()
            ),
        )
    })?;
    write_message(&mut stream, request)?;
    let response = read_message(&mut stream)?;
    if response["api_version"].as_u64() != Some(API_VERSION) {
        return Err(invalid("incompatible local API version; expected 1"));
    }
    if let Some(error) = response.get("error") {
        return Err(invalid(
            error
                .as_str()
                .unwrap_or("local service rejected the request"),
        ));
    }
    if response.get("data").is_none() {
        return Err(invalid("invalid service response"));
    }
    Ok(response)
}
