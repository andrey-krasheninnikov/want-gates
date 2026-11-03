mod common;
use common::Service;
use serde_json::Value;
use std::process::{Command, Output};

fn call(service: &Service, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(args)
        .arg("--socket")
        .arg(&service.socket)
        .output()
        .unwrap()
}
fn ok(service: &Service, args: &[&str]) -> Value {
    let output = call(service, args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice::<Value>(&output.stdout).unwrap()["data"].clone()
}

#[test]
fn forti_import_is_private_and_survives_restart_without_claiming_access() {
    let mut service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Forti company"]);
    let path = service.directory.path().join("office.conf");
    std::fs::write(
        &path,
        "host = vpn.example.test\nport = 443\nrealm = office\n",
    )
    .unwrap();
    let connection = ok(
        &service,
        &[
            "connection",
            "import",
            "--group",
            group["id"].as_str().unwrap(),
            "--name",
            "Office",
            "--protocol",
            "forti",
            "--file",
            path.to_str().unwrap(),
        ],
    );
    assert_eq!(connection["protocol"], "forti");
    assert_eq!(connection["validation"], "structural");
    assert_eq!(connection["authentication"], "not_attempted");
    assert_eq!(connection["capabilities"], serde_json::json!([]));
    assert!(!connection.to_string().contains("vpn.example.test"));
    let login = call(
        &service,
        &["connection", "login", connection["id"].as_str().unwrap()],
    );
    assert!(!login.status.success());
    assert!(
        String::from_utf8_lossy(&login.stderr)
            .contains("requires a current routing preview and apply")
    );
    assert!(service.stop().success());
    service.start_again();
    assert_eq!(
        ok(
            &service,
            &["connection", "show", connection["id"].as_str().unwrap()]
        ),
        connection
    );
}

#[test]
fn forti_assets_are_packaged_and_unsafe_native_options_never_reach_the_service() {
    let service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Forti assets"]);
    let directory = service.directory.path().join("profiles");
    std::fs::create_dir_all(directory.join("keys")).unwrap();
    let ca = directory.join("keys/ca.pem");
    std::fs::write(&ca, include_str!("fixtures/health-ca.pem")).unwrap();
    let path = directory.join("office.conf");
    let args = [
        "connection",
        "import",
        "--group",
        group["id"].as_str().unwrap(),
        "--name",
        "Office",
        "--protocol",
        "forti",
        "--file",
        path.to_str().unwrap(),
    ];
    std::fs::write(&path, "host = vpn.example.test\nca-file = keys/ca.pem\n").unwrap();
    let connection = ok(&service, &args);
    std::fs::remove_file(ca).unwrap();
    assert_eq!(
        ok(
            &service,
            &["connection", "show", connection["id"].as_str().unwrap()]
        )["protocol"],
        "forti"
    );
    std::os::unix::fs::symlink("/etc/passwd", directory.join("linked.pem")).unwrap();
    for option in [
        "password = private-secret-marker",
        "cookie = private-secret-marker",
        "pppd-plugin = /tmp/plugin.so",
        "pppd-call = peer",
        "pinentry = /tmp/program",
        "insecure-ssl = 1",
        "min-tls = 1.0",
        "ca-file = /etc/passwd",
        "ca-file = ../outside",
        "ca-file = linked.pem",
        "host = other.example.test",
        "port = 0",
        "unknown = private-secret-marker",
    ] {
        std::fs::write(&path, format!("host = vpn.example.test\n{option}\n")).unwrap();
        let output = call(&service, &args);
        assert!(!output.status.success(), "accepted {option}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-secret-marker"));
    }
    assert_eq!(
        ok(&service, &["connection", "list"])
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
