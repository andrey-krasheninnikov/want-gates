use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::Builder;

mod common;
use common::{Service, cli, status};

#[test]
fn help_version_and_argument_failures() {
    assert!(cli(&["--help"]).status.success());
    let version = cli(&["--version"]);
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        format!("wgates {}", env!("CARGO_PKG_VERSION"))
    );
    for args in [
        vec!["unknown"],
        vec!["status", "--state-dir", "/tmp"],
        vec!["status", "--socket"],
        vec!["status", "--socket", "relative.sock"],
        vec!["--version", "extra"],
    ] {
        let output = cli(&args);
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn status_and_graceful_shutdown_leave_empty_state() {
    let mut service = Service::start();
    let output = status(&service.socket);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["api_version"], 1);
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["ready"], true);
    assert!(output.stderr.is_empty());
    assert_eq!(fs::metadata(&service.socket).unwrap().mode() & 0o777, 0o660);
    assert_eq!(fs::metadata(&service.state).unwrap().mode() & 0o777, 0o700);
    assert_eq!(fs::read_dir(&service.state).unwrap().count(), 0);
    assert!(service.stop().success());
    assert!(!service.socket.exists());
    assert!(service.state.is_dir());
}

#[test]
fn unavailable_service_fails_with_an_actionable_error() {
    let directory = Builder::new().prefix("wgates-").tempdir_in("/tmp").unwrap();
    let output = status(&directory.path().join("missing.sock"));
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("start wgates.service")
    );
}

fn fake_status(response: &[u8]) -> Output {
    let directory = Builder::new().prefix("wgates-").tempdir_in("/tmp").unwrap();
    let socket = directory.path().join("fake.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let response = response.to_vec();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut request = String::new();
                    BufReader::new(&stream).read_line(&mut request).unwrap();
                    let request: Value = serde_json::from_str(&request).unwrap();
                    assert_eq!(request["command"], "status");
                    let _ = stream.write_all(&response);
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "CLI did not connect");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("{error}"),
            }
        }
    });
    let output = status(&socket);
    server.join().unwrap();
    output
}

#[test]
fn incompatible_and_invalid_service_responses_fail_closed() {
    for response in [
        b"{\"api_version\":999,\"version\":\"9\",\"ready\":true}\n".to_vec(),
        b"{\"api_version\":1,\"version\":\"0.1.0\",\"ready\":false}\n".to_vec(),
        b"{\"api_version\":1,\"ready\":true}\n".to_vec(),
        b"not JSON\n".to_vec(),
        b"{\"api_version\":1}".to_vec(),
        vec![b'x'; 4097],
    ] {
        let output = fake_status(&response);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn buffered_status_is_accepted_after_the_peer_closes() {
    let output = fake_status(b"{\"api_version\":1,\"version\":\"0.1.0\",\"ready\":true}\n");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["ready"], true);
}

#[test]
fn malformed_requests_do_not_stop_the_service() {
    let mut service = Service::start();
    for request in [
        b"{\"api_version\":999,\"command\":\"status\"}\n".to_vec(),
        b"{\"api_version\":1,\"command\":\"unknown\"}\n".to_vec(),
        b"invalid\n".to_vec(),
        vec![b'x'; 4097],
    ] {
        let mut stream = UnixStream::connect(&service.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream.write_all(&request).unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["api_version"], 1);
        assert!(response["error"].is_string());
        let output = status(&service.socket);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(service.stop().success());
}

#[test]
fn duplicate_service_preserves_the_active_socket() {
    let mut service = Service::start();
    let before = fs::metadata(&service.socket).unwrap().ino();
    let output = Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(["serve", "--socket"])
        .arg(&service.socket)
        .arg("--state-dir")
        .arg(&service.state)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::metadata(&service.socket).unwrap().ino(), before);
    assert!(status(&service.socket).status.success());
    assert!(service.stop().success());
}

#[test]
fn fragmented_requests_wait_for_the_complete_message() {
    let mut service = Service::start();
    let mut stream = UnixStream::connect(&service.socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(b"{\"api_version\":1,").unwrap();
    thread::sleep(Duration::from_millis(50));
    stream.write_all(b"\"command\":\"status\"}\n").unwrap();
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    let value: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["ready"], true);
    assert!(service.stop().success());
}

#[test]
fn unsafe_state_permissions_are_rejected_without_changing_them() {
    let directory = Builder::new().prefix("wgates-").tempdir_in("/tmp").unwrap();
    let state = directory.path().join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
    let socket = directory.path().join("control.sock");
    let output = Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(["serve", "--socket"])
        .arg(&socket)
        .arg("--state-dir")
        .arg(&state)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!socket.exists());
    assert_eq!(fs::metadata(&state).unwrap().mode() & 0o777, 0o755);
}

#[test]
fn existing_files_and_replaced_socket_paths_are_preserved() {
    let directory = Builder::new().prefix("wgates-").tempdir_in("/tmp").unwrap();
    let socket = directory.path().join("control.sock");
    fs::write(&socket, b"keep this file").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(["serve", "--socket"])
        .arg(&socket)
        .arg("--state-dir")
        .arg(directory.path().join("state"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(&socket).unwrap(), b"keep this file");

    let mut service = Service::start();
    fs::rename(&service.socket, service.directory.path().join("saved.sock")).unwrap();
    fs::write(&service.socket, b"retain the replacement").unwrap();
    assert!(!service.stop().success());
    assert_eq!(
        fs::read(&service.socket).unwrap(),
        b"retain the replacement"
    );
}

#[test]
fn shutdown_is_bounded_with_an_incomplete_request() {
    let mut service = Service::start();
    let mut stream = UnixStream::connect(&service.socket).unwrap();
    stream.write_all(b"{").unwrap();
    thread::sleep(Duration::from_millis(100));
    let before = Instant::now();
    assert!(service.stop().success());
    assert!(before.elapsed() < Duration::from_secs(4));
}
