use crate::{invalid, secure_directory};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const MAX_PROFILE: usize = 1024 * 1024;
const MAX_CONFIG: usize = 16 * 1024 * 1024;
const PAGE_SIZE: usize = 100;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    id: String,
    name: String,
    revision: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Connection {
    id: String,
    group_id: String,
    name: String,
    protocol: String,
    revision: u64,
    profile_ref: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema_version: u64,
    revision: u64,
    groups: Vec<Group>,
    connections: Vec<Connection>,
}

pub struct Store {
    root: PathBuf,
    config: Config,
    _lock: File,
}

pub fn private_read(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid takes no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o600 != 0o600
    {
        return Err(invalid(
            "state files must be private regular files owned by the service user",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("state file exceeds its size limit"));
    }
    Ok(bytes)
}

pub fn name(value: &Value) -> io::Result<String> {
    let name = text(value)?;
    if name.trim() != name
        || name.is_empty()
        || name.chars().count() > 128
        || name.chars().any(char::is_control)
    {
        return Err(invalid(
            "name must contain 1 to 128 characters without surrounding whitespace or controls",
        ));
    }
    Ok(name.to_owned())
}

pub fn text(value: &Value) -> io::Result<&str> {
    value
        .as_str()
        .ok_or_else(|| invalid("a required string field is missing or invalid"))
}

impl Store {
    pub fn open(root: &Path) -> io::Result<Self> {
        let lock = File::open(root)?;
        // SAFETY: the descriptor stays open for the lifetime of Store; flock changes only its advisory lock.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(invalid(
                "state directory is already in use or cannot be locked",
            ));
        }
        let config = match private_read(&root.join("config.json"), MAX_CONFIG) {
            Ok(bytes) => serde_json::from_slice::<Config>(&bytes).map_err(|_| {
                invalid("invalid saved configuration; repair it offline; state was retained")
            })?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Config {
                schema_version: 1,
                revision: 0,
                groups: Vec::new(),
                connections: Vec::new(),
            },
            Err(error) => return Err(error),
        };
        if config.schema_version != 1 {
            return Err(invalid("unsupported saved configuration version"));
        }
        let mut ids = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        for group in &config.groups {
            if id_number(&group.id, 'g').is_none_or(|n| n > group.revision)
                || group.revision == 0
                || group.revision > config.revision
                || !ids.insert(&group.id)
                || !names.insert(&group.name)
                || name(&json!(group.name)).is_err()
            {
                return Err(invalid(
                    "invalid saved group references; state was retained",
                ));
            }
        }
        let secrets = root.join("secrets");
        match fs::symlink_metadata(&secrets) {
            Ok(_) => secure_directory(&secrets, 0o700, 0o077)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut names = std::collections::HashSet::new();
        for connection in &config.connections {
            if connection.protocol != "vless"
                || id_number(&connection.id, 'c').is_none_or(|n| n > connection.revision)
                || connection.revision == 0
                || connection.revision > config.revision
                || !config.groups.iter().any(|g| g.id == connection.group_id)
                || !ids.insert(&connection.id)
                || !names.insert((&connection.group_id, &connection.name))
                || name(&json!(connection.name)).is_err()
                || !profile_filename(&connection.profile_ref)
                || !connection
                    .profile_ref
                    .starts_with(&format!("{}-r", connection.id))
                || connection
                    .profile_ref
                    .strip_suffix(".json")
                    .and_then(|s| s.split_once("-r"))
                    .and_then(|(_, r)| r.parse::<u64>().ok())
                    .is_none_or(|r| r > connection.revision || r == 0)
            {
                return Err(invalid(
                    "invalid saved connection references; state was retained",
                ));
            }
            let bytes = private_read(&secrets.join(&connection.profile_ref), MAX_PROFILE)?;
            let input = std::str::from_utf8(&bytes)
                .map_err(|_| invalid("invalid saved profile; state was retained"))?;
            crate::profile::parse(input)?;
        }
        let store = Self {
            root: root.to_owned(),
            config,
            _lock: lock,
        };
        if store.config.revision == 0
            && secrets.exists()
            && fs::read_dir(&secrets)?.next().is_some()
        {
            return Err(invalid(
                "configuration missing beside saved profiles; state was retained",
            ));
        }
        store.clean_profiles()?;
        Ok(store)
    }

    fn commit(&mut self, config: Config) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(&config)?;
        if bytes.len() > MAX_CONFIG {
            return Err(invalid("configuration exceeds 16 MiB; no changes saved"));
        }
        let destination = self.root.join("config.json");
        match private_read(&destination, MAX_CONFIG) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && self.config.revision == 0 => {}
            Err(error) => return Err(error),
        }
        let temporary = self.root.join(format!(
            ".config-{}-{}.tmp",
            std::process::id(),
            config.revision
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &destination)
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        self.config = config;
        File::open(&self.root)?.sync_all().map_err(|_| {
            io::Error::other(
                "configuration saved but durability is uncertain; inspect state before retrying",
            )
        })
    }

    pub fn dispatch(&mut self, request: &Value) -> io::Result<Value> {
        let command = text(&request["command"])?;
        let fields: &[&str] = match command {
            "group.create" => &["name"],
            "group.list" => &["offset", "list_revision"],
            "group.show" | "connection.show" => &["id"],
            "group.update" => &["id", "expected_revision", "name"],
            "group.delete" | "connection.delete" => &["id", "expected_revision"],
            "connection.list" => &["group_id", "sort", "offset", "list_revision"],
            "connection.import" => &["name", "group_id", "protocol", "profile"],
            "connection.update" => &["id", "expected_revision", "name", "group_id", "profile"],
            _ => return Err(invalid("unsupported command")),
        };
        if request.as_object().is_none_or(|m| {
            m.keys()
                .any(|k| k != "api_version" && k != "command" && !fields.contains(&k.as_str()))
        }) {
            return Err(invalid("unexpected local API request field"));
        }
        let mut config = self.config.clone();
        let revision = config
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("configuration revision exhausted"))?;
        let mut new_profile = None;
        let result = match command {
            "group.list" => {
                let mut groups = config.groups;
                groups.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
                return self.page(request, groups.iter().map(|g| json!(g)).collect());
            }
            "group.create" => {
                let name = name(&request["name"])?;
                if config.groups.iter().any(|g| g.name == name) {
                    return Err(invalid("group name already exists"));
                }
                let group = Group {
                    id: format!("g{revision}"),
                    name,
                    revision,
                };
                config.groups.push(group.clone());
                json!(group)
            }
            "group.show" | "group.update" | "group.delete" => {
                let id = text(&request["id"])?;
                let index = config
                    .groups
                    .iter()
                    .position(|g| g.id == id)
                    .ok_or_else(|| invalid("group not found"))?;
                if command == "group.show" {
                    return Ok(json!({"data":config.groups[index]}));
                }
                if request["expected_revision"].as_u64() != Some(config.groups[index].revision) {
                    return Err(invalid("revision conflict; inspect the object and retry"));
                }
                if command == "group.delete" {
                    if config.connections.iter().any(|c| c.group_id == id) {
                        return Err(invalid(
                            "group is referenced by connections; move or remove them first",
                        ));
                    }
                    json!(config.groups.remove(index))
                } else {
                    let name = name(&request["name"])?;
                    if config.groups.iter().any(|g| g.name == name && g.id != id) {
                        return Err(invalid("group name already exists"));
                    }
                    config.groups[index].name = name;
                    config.groups[index].revision = revision;
                    json!(config.groups[index])
                }
            }
            "connection.list" => {
                let filter = request.get("group_id").map(text).transpose()?;
                if let Some(id) = filter
                    && !config.groups.iter().any(|g| g.id == id)
                {
                    return Err(invalid("group not found"));
                }
                let sort = request
                    .get("sort")
                    .map(text)
                    .transpose()?
                    .unwrap_or("group");
                if sort != "group" && sort != "name" {
                    return Err(invalid("sort must be group or name"));
                }
                let mut connections: Vec<_> = config
                    .connections
                    .iter()
                    .filter(|c| filter.is_none_or(|id| c.group_id == id))
                    .collect();
                let group_name = |id: &str| {
                    config
                        .groups
                        .iter()
                        .find(|g| g.id == id)
                        .unwrap()
                        .name
                        .as_str()
                };
                connections.sort_by(|a, b| {
                    if sort == "name" {
                        (&a.name, &a.id).cmp(&(&b.name, &b.id))
                    } else {
                        (group_name(&a.group_id), &a.name, &a.id).cmp(&(
                            group_name(&b.group_id),
                            &b.name,
                            &b.id,
                        ))
                    }
                });
                return self.page(request, connections.iter().map(|c| summary(c)).collect());
            }
            "connection.import" => {
                protocol(&request["protocol"])?;
                let group_id = text(&request["group_id"])?;
                if !config.groups.iter().any(|g| g.id == group_id) {
                    return Err(invalid("group not found"));
                }
                let name = name(&request["name"])?;
                if config
                    .connections
                    .iter()
                    .any(|c| c.group_id == group_id && c.name == name)
                {
                    return Err(invalid("connection name already exists in group"));
                }
                let profile = crate::profile::parse(text(&request["profile"])?)?;
                let connection = Connection {
                    id: format!("c{revision}"),
                    group_id: group_id.to_owned(),
                    name,
                    protocol: "vless".to_owned(),
                    revision,
                    profile_ref: format!("c{revision}-r{revision}.json"),
                };
                new_profile = Some((connection.profile_ref.clone(), profile));
                config.connections.push(connection.clone());
                summary(&connection)
            }
            "connection.show" | "connection.update" | "connection.delete" => {
                let id = text(&request["id"])?;
                let index = config
                    .connections
                    .iter()
                    .position(|c| c.id == id)
                    .ok_or_else(|| invalid("connection not found"))?;
                if command == "connection.show" {
                    return Ok(json!({"data":summary(&config.connections[index])}));
                }
                if request["expected_revision"].as_u64() != Some(config.connections[index].revision)
                {
                    return Err(invalid("revision conflict; inspect the object and retry"));
                }
                if command == "connection.delete" {
                    summary(&config.connections.remove(index))
                } else {
                    if ["name", "group_id", "profile"]
                        .iter()
                        .all(|k| request.get(k).is_none())
                    {
                        return Err(invalid("update requires name, group or profile"));
                    }
                    let mut connection = config.connections[index].clone();
                    if let Some(value) = request.get("name") {
                        connection.name = name(value)?;
                    }
                    if let Some(value) = request.get("group_id") {
                        connection.group_id = text(value)?.to_owned();
                    }
                    if !config.groups.iter().any(|g| g.id == connection.group_id) {
                        return Err(invalid("group not found"));
                    }
                    if config.connections.iter().any(|c| {
                        c.id != id && c.group_id == connection.group_id && c.name == connection.name
                    }) {
                        return Err(invalid("connection name already exists in group"));
                    }
                    if let Some(value) = request.get("profile") {
                        let profile = crate::profile::parse(text(value)?)?;
                        connection.profile_ref = format!("{id}-r{revision}.json");
                        new_profile = Some((connection.profile_ref.clone(), profile));
                    }
                    connection.revision = revision;
                    config.connections[index] = connection.clone();
                    summary(&connection)
                }
            }
            _ => return Err(invalid("unsupported command")),
        };
        config.revision = revision;
        if let Some((reference, profile)) = &new_profile {
            let directory = self.root.join("secrets");
            secure_directory(&directory, 0o700, 0o077)?;
            let bytes = serde_json::to_vec(profile)?;
            if bytes.len() > MAX_PROFILE {
                return Err(invalid("normalized profile exceeds 1 MiB"));
            }
            let written = (|| -> io::Result<()> {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(directory.join(reference))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                File::open(&directory)?.sync_all()?;
                File::open(&self.root)?.sync_all()
            })();
            if let Err(error) = written {
                let _ = self.clean_profiles();
                return Err(error);
            }
        }
        let saved = self.commit(config);
        let cleanup = self.clean_profiles();
        saved?;
        cleanup.map_err(|_| {
            io::Error::other(
                "configuration saved; unused profile cleanup failed; inspect state before retrying",
            )
        })?;
        Ok(json!({"data":result}))
    }

    fn clean_profiles(&self) -> io::Result<()> {
        let directory = self.root.join("secrets");
        let entries = match fs::read_dir(&directory) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if profile_filename(name)
                && !self
                    .config
                    .connections
                    .iter()
                    .any(|c| c.profile_ref == name)
            {
                private_read(&entry.path(), MAX_PROFILE)?;
                fs::remove_file(entry.path())?;
            }
        }
        File::open(directory)?.sync_all()
    }

    fn page(&self, request: &Value, items: Vec<Value>) -> io::Result<Value> {
        if request.get("list_revision").is_some()
            && request["list_revision"].as_u64() != Some(self.config.revision)
        {
            return Err(invalid("configuration changed during listing; retry"));
        }
        let offset = request
            .get("offset")
            .map(|v| v.as_u64().and_then(|n| usize::try_from(n).ok()))
            .unwrap_or(Some(0))
            .ok_or_else(|| invalid("invalid list offset"))?;
        if offset > items.len() {
            return Err(invalid("invalid list offset"));
        }
        let end = offset.saturating_add(PAGE_SIZE).min(items.len());
        Ok(
            json!({"data":items[offset..end], "list_revision":self.config.revision,
            "next_offset":if end < items.len() {Some(end)} else {None}}),
        )
    }
}

fn profile_filename(name: &str) -> bool {
    let Some((connection, revision)) = name.strip_suffix(".json").and_then(|s| s.split_once("-r"))
    else {
        return false;
    };
    [connection.strip_prefix('c'), Some(revision)]
        .iter()
        .all(|s| s.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())))
}
fn protocol(value: &Value) -> io::Result<()> {
    match text(value)? {
        "vless" => Ok(()),
        "openvpn" | "forti" | "wireguard" | "netbird" => Err(invalid(
            "protocol adapter unavailable; only VLESS profile import is implemented",
        )),
        _ => Err(invalid("unsupported protocol")),
    }
}
fn summary(c: &Connection) -> Value {
    json!({"id":c.id,"group_id":c.group_id,"name":c.name,"protocol":c.protocol,"revision":c.revision,
        "validation":"structural","runtime":"unavailable","runtime_reason":"routing_not_implemented",
        "authentication":"not_attempted","capabilities":[]})
}

fn id_number(id: &str, prefix: char) -> Option<u64> {
    let n = id.strip_prefix(prefix)?.parse::<u64>().ok()?;
    (n > 0 && id == format!("{prefix}{n}")).then_some(n)
}
