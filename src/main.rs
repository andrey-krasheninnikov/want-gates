mod capability;
mod domain;
mod health;
mod management;
mod native;
#[cfg(target_os = "linux")]
mod native_runtime;
mod openvpn;
#[cfg(target_os = "linux")]
mod openvpn_auth;
mod panel;
mod policy;
mod probe;
mod profile;
mod routing;
mod store;

use serde_json::{Value, json};
use std::env;
use std::fs::{self, DirBuilder, Permissions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const API_VERSION: u64 = 1;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
// Include JSON escaping of a 1 MiB profile and request metadata.
const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const HELP: &str = "Want Gates local control service

Usage:
  wgates serve [--socket PATH] [--state-dir PATH] [--native-socket PATH]
  wgates status [--socket PATH]
  wgates group create --name NAME [--socket PATH]
  wgates group list|show ID|delete ID [--socket PATH]
  wgates group update ID [--name NAME] [--primary CONNECTION_ID|-] [--probe-file PATH|-] [--fallbacks ID,...|-] [--healthcheck-file PATH|-]
  wgates connection import --group ID --name NAME --protocol vless|openvpn --file PATH|- [--dns URI] [--capabilities LIST|all|none]
  wgates connection verify ID
  wgates connection login ID [--file PATH|-] [--remember]
  wgates connection logout ID|restart ID|forget-auth ID
  wgates connection list [--group ID] [--sort group|name]
  wgates connection show ID|update ID [--name NAME] [--group ID] [--file PATH|-] [--dns URI|-] [--capabilities LIST|all|none]|delete ID
  wgates rule create --group ID --destination DOMAIN_OR_IP_OR_CIDR
  wgates rule list [--group ID]
  wgates rule show ID|update ID [--group ID] [--destination DOMAIN_OR_IP_OR_CIDR]|delete ID
  wgates panel configure --file PATH|-
  wgates panel preflight
  wgates routing preview|status
  wgates routing apply PLAN_ID|recover PLAN_ID
  wgates --version

All management commands accept --socket PATH. Saving changes desired state only.
Routing requires 3x-ui 3.8.5 and Xray 26.9.9; apply explicitly names a reviewed plan.

Defaults:
  --socket     /run/wgates/control.sock
  --state-dir  /var/lib/wgates
  --native-socket /run/wgates-native/control.sock

Paths must be absolute. Status reports control-service readiness, not VPN health.
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wgates: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    let mut args = env::args_os().skip(1);
    let Some(command) = args.next() else {
        print!("{HELP}");
        return Ok(());
    };
    if command == "--help" || command == "-h" {
        print!("{HELP}");
        return Ok(());
    }
    if command == "--version" || command == "-V" {
        if args.next().is_some() {
            return Err(invalid("unexpected arguments after --version"));
        }
        println!("wgates {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if command == "native-runtime" || command == "native-cleanup" {
        #[cfg(target_os = "linux")]
        {
            return native_runtime::run(args, command == "native-cleanup");
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err(invalid("native runtime requires Linux"));
        }
    }
    if command == "group"
        || command == "connection"
        || command == "rule"
        || command == "panel"
        || command == "routing"
    {
        return management::run(command.to_str().unwrap(), args);
    }
    if command != "serve" && command != "status" {
        return Err(invalid("unknown command; run wgates --help"));
    }
    let mut socket = PathBuf::from("/run/wgates/control.sock");
    let mut state = PathBuf::from("/var/lib/wgates");
    let mut native_socket = PathBuf::from(native::DEFAULT_SOCKET);
    while let Some(option) = args.next() {
        if option == "--help" || option == "-h" {
            print!("{HELP}");
            return Ok(());
        }
        let destination = if option == "--socket" {
            &mut socket
        } else if option == "--state-dir" && command == "serve" {
            &mut state
        } else if option == "--native-socket" && command == "serve" {
            &mut native_socket
        } else {
            return Err(invalid("unknown option; run wgates --help"));
        };
        *destination = args
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| invalid("a path is required after --socket or --state-dir"))?;
        if !destination.is_absolute() {
            return Err(invalid("socket and state paths must be absolute"));
        }
    }
    if command == "serve" {
        serve(&socket, &state, &native_socket)
    } else {
        status(&socket)
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn secure_directory(path: &Path, mode: u32, forbidden: u32) -> io::Result<()> {
    match DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & forbidden != 0
        || metadata.mode() & 0o700 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must be a directory owned by the service user with restricted permissions",
                path.display()
            ),
        ));
    }
    Ok(())
}

struct OwnedSocket {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl OwnedSocket {
    fn cleanup(&self) -> io::Result<()> {
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && metadata.dev() == self.device
                    && metadata.ino() == self.inode =>
            {
                fs::remove_file(&self.path)
            }
            Ok(_) => Err(io::Error::other(
                "socket path was replaced; the replacement was retained",
            )),
        }
    }
}

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("wgates: socket cleanup: {error}");
        }
    }
}

fn serve(socket: &Path, state: &Path, native_socket: &Path) -> io::Result<()> {
    let parent = socket
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| invalid("socket must have a parent directory"))?;
    secure_directory(parent, 0o750, 0o027)?;
    secure_directory(state, 0o700, 0o077)?;
    let mut store = store::Store::open(state)?;
    let listener = UnixListener::bind(socket).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot bind {}: {error}; an existing socket or file is never replaced",
                socket.display()
            ),
        )
    })?;
    let metadata = fs::symlink_metadata(socket)?;
    let owned = OwnedSocket {
        path: socket.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    fs::set_permissions(socket, Permissions::from_mode(0o660))?;
    listener.set_nonblocking(true)?;
    let stopping = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stopping))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stopping))?;
    let mut routing = routing::Service::new(state, Arc::clone(&stopping), native_socket)?;
    eprintln!("wgates: control service ready at {}", socket.display());
    // Keep configuration writes serialized while network operations use one worker.
    while !stopping.load(Ordering::Relaxed) {
        routing.reap();
        match listener.accept() {
            Ok((mut stream, _)) => {
                if let Err(error) = handle(&mut stream, &mut store, &mut routing) {
                    eprintln!("wgates: local request failed: {error}");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                routing.tick();
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    routing.finish();
    drop(listener);
    owned.cleanup()
}

fn read_message(stream: &mut UnixStream) -> io::Result<Value> {
    read_message_with_timeout(stream, IO_TIMEOUT)
}
fn read_message_with_timeout(stream: &mut UnixStream, timeout: Duration) -> io::Result<Value> {
    let deadline = Instant::now() + timeout;
    let mut message = Vec::new();
    let mut buffer = [0; 256];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "local API response timed out")
            })?;
        // Poll preserves buffered data when a peer closes before the next read on macOS.
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll borrows one initialized entry containing this live stream's descriptor.
        let ready = unsafe { libc::poll(&mut descriptor, 1, remaining.as_millis().max(1) as i32) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local API read timed out",
            ));
        }
        let count = match stream.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result.map_err(|error| {
                io::Error::new(error.kind(), format!("reading local API message: {error}"))
            })?,
        };
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "local API message ended before a newline",
            ));
        }
        let end = buffer[..count].iter().position(|byte| *byte == b'\n');
        let length = end.unwrap_or(count);
        if message.len() + length > MAX_MESSAGE {
            return Err(invalid("local API message exceeds 4 MiB"));
        }
        message.extend_from_slice(&buffer[..length]);
        if let Some(end) = end {
            if !buffer[end + 1..count].iter().all(u8::is_ascii_whitespace) {
                return Err(invalid("expected one local API message"));
            }
            return serde_json::from_slice(&message)
                .map_err(|_| invalid("invalid JSON in local API message"));
        }
    }
}

fn write_message(stream: &mut UnixStream, value: &Value) -> io::Result<()> {
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("setting local write timeout: {error}"),
            )
        })?;
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_MESSAGE {
        return Err(invalid("local API message exceeds 4 MiB"));
    }
    stream.write_all(&bytes)?;
    stream.write_all(b"\n")
}

fn handle(
    stream: &mut UnixStream,
    store: &mut store::Store,
    routing: &mut routing::Service,
) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    let response = match read_message(stream) {
        Err(_) => json!({"api_version": API_VERSION, "error": "invalid or incomplete request"}),
        Ok(request) if request["api_version"].as_u64() != Some(API_VERSION) => {
            json!({"api_version": API_VERSION, "error": "incompatible API version; expected 1"})
        }
        Ok(request) if request["command"].as_str() != Some("status") => {
            let command = request["command"].as_str().unwrap_or("");
            if command.starts_with("routing.")
                || command.starts_with("panel.")
                || command == "connection.verify"
                || matches!(
                    command,
                    "connection.login"
                        | "connection.logout"
                        | "connection.restart"
                        | "connection.forget-auth"
                )
            {
                let response = match routing.dispatch(&request, store, stream) {
                    Ok(Some(mut response)) => {
                        response["api_version"] = json!(API_VERSION);
                        response
                    }
                    Ok(None) => return Ok(()),
                    Err(error) => json!({"api_version":API_VERSION,"error":error.to_string()}),
                };
                return write_message(stream, &response);
            }
            if routing.busy() && !command.ends_with(".show") && !command.ends_with(".list") {
                return write_message(
                    stream,
                    &json!({"api_version":API_VERSION,"error":"routing operation in progress; configuration writes are locked"}),
                );
            }
            match store.dispatch(&request) {
                Ok(mut response) => {
                    if command.starts_with("connection.") {
                        routing.describe_connections(&mut response, store.config());
                    }
                    response["api_version"] = json!(API_VERSION);
                    response
                }
                Err(error) => json!({"api_version": API_VERSION, "error": error.to_string()}),
            }
        }
        Ok(_) => json!({
            "api_version": API_VERSION,
            "version": env!("CARGO_PKG_VERSION"),
            "ready": true
        }),
    };
    write_message(stream, &response)
}

fn status(socket: &Path) -> io::Result<()> {
    let mut stream = UnixStream::connect(socket).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot reach {}: {error}; start wgates.service and check socket access",
                socket.display()
            ),
        )
    })?;
    write_message(
        &mut stream,
        &json!({"api_version": API_VERSION, "command": "status"}),
    )?;
    let response = read_message(&mut stream)?;
    if response["api_version"].as_u64() != Some(API_VERSION) {
        return Err(invalid("incompatible local API version; expected 1"));
    }
    if response.get("error").is_some() {
        return Err(io::Error::other(
            "the local service rejected the status request",
        ));
    }
    if response["ready"].as_bool() != Some(true)
        || response["version"].as_str().is_none_or(str::is_empty)
    {
        return Err(invalid("invalid or not-ready local service status"));
    }
    println!("{response}");
    Ok(())
}
