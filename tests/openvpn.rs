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
fn profile() -> String {
    format!(
        "client\ndev tun\nproto udp\nremote vpn.example.test 1194\nremote-cert-tls server\nauth-user-pass\n<ca>\n{}\n</ca>\n",
        include_str!("fixtures/health-ca.pem")
    )
}

#[test]
fn openvpn_import_keeps_profiles_private_and_preserves_them_across_restart() {
    let mut service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "OpenVPN company"]);
    let path = service.directory.path().join("client.ovpn");
    std::fs::write(&path, profile()).unwrap();
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
            "openvpn",
            "--file",
            path.to_str().unwrap(),
        ],
    );
    assert_eq!(connection["protocol"], "openvpn");
    assert_eq!(connection["validation"], "structural");
    assert_eq!(connection["authentication"], "not_attempted");
    assert_eq!(connection["capabilities"], serde_json::json!([]));
    assert!(!connection.to_string().contains("BEGIN CERTIFICATE"));
    let saved = std::fs::read_to_string(service.state.join("config.json")).unwrap();
    assert!(!saved.contains("vpn.example.test"));
    assert!(!saved.contains("BEGIN CERTIFICATE"));
    assert!(service.stop().success());
    service.start_again();
    let readback = ok(
        &service,
        &["connection", "show", connection["id"].as_str().unwrap()],
    );
    assert_eq!(readback, connection);
}

#[test]
fn relative_assets_are_packaged_but_hooks_and_path_escapes_are_rejected() {
    let service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Assets"]);
    let directory = service.directory.path().join("profiles");
    std::fs::create_dir(&directory).unwrap();
    std::fs::create_dir(directory.join("keys")).unwrap();
    std::fs::write(
        directory.join("keys/ca.pem"),
        include_str!("fixtures/health-ca.pem"),
    )
    .unwrap();
    let path = directory.join("client.ovpn");
    let source = "client\ndev tun\nremote 127.0.0.1 1194\nca \"keys/ca.pem\"\nauth-user-pass\n";
    std::fs::write(&path, source).unwrap();
    let args = [
        "connection",
        "import",
        "--group",
        group["id"].as_str().unwrap(),
        "--name",
        "Assets",
        "--protocol",
        "openvpn",
        "--file",
        path.to_str().unwrap(),
    ];
    let connection = ok(&service, &args);
    std::fs::remove_file(directory.join("keys/ca.pem")).unwrap();
    assert_eq!(
        ok(
            &service,
            &["connection", "show", connection["id"].as_str().unwrap()]
        )["protocol"],
        "openvpn"
    );
    std::os::unix::fs::symlink("../../outside.pem", directory.join("linked.pem")).unwrap();
    std::fs::write(
        service.directory.path().join("outside.pem"),
        include_str!("fixtures/health-ca.pem"),
    )
    .unwrap();
    for unsafe_option in [
        "up /tmp/marker",
        "plugin /tmp/module.so",
        "script-security 2",
        "config nested.ovpn",
        "management /tmp/socket unix",
        "ca ../outside.pem",
        "ca /etc/passwd",
        "ca linked.pem",
    ] {
        let bad = if unsafe_option.starts_with("ca ") {
            source.replace("ca \"keys/ca.pem\"", unsafe_option)
        } else {
            format!("{}\n{unsafe_option}\n", profile())
        };
        std::fs::write(&path, bad).unwrap();
        let rejected = call(&service, &args);
        assert!(!rejected.status.success(), "accepted {unsafe_option}");
        assert!(!String::from_utf8_lossy(&rejected.stderr).contains("BEGIN CERTIFICATE"));
    }
    assert_eq!(
        ok(&service, &["connection", "list"])
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn unknown_profile_text_is_not_echoed_in_errors() {
    let service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Redaction"]);
    let path = service.directory.path().join("bad.ovpn");
    std::fs::write(&path, format!("{}\nprofile-secret-marker\n", profile())).unwrap();
    let output = call(
        &service,
        &[
            "connection",
            "import",
            "--group",
            group["id"].as_str().unwrap(),
            "--name",
            "Bad",
            "--protocol",
            "openvpn",
            "--file",
            path.to_str().unwrap(),
        ],
    );
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("profile-secret-marker"));
}

#[test]
fn login_requires_applied_preparation_and_never_accepts_secret_arguments() {
    let service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Authentication"]);
    let path = service.directory.path().join("client.ovpn");
    std::fs::write(&path, profile()).unwrap();
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
            "openvpn",
            "--file",
            path.to_str().unwrap(),
        ],
    );
    let id = connection["id"].as_str().unwrap();
    let output = call(&service, &["connection", "login", id]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("requires a current routing preview and apply")
    );
    let output = call(
        &service,
        &["connection", "login", id, "--password", "credential-marker"],
    );
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("credential-marker"));
    assert_eq!(
        ok(&service, &["connection", "show", id])["authentication"],
        "not_attempted"
    );
}

#[test]
fn packaged_inline_data_cannot_inject_runtime_directives() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Inline safety"]);
    let profile = serde_json::json!({"protocol":"openvpn","options":[["client"],["dev","tun"],["remote","10.1.2.3","1194"]],"inline":{"ca":format!("{}\n</ca>\nscript-security 2\nup /tmp/forbidden-hook\n<ca>\n",include_str!("fixtures/health-ca.pem"))}});
    let request = serde_json::json!({"api_version":1,"command":"connection.import","name":"Injected","group_id":group["id"],"protocol":"openvpn","profile":profile.to_string()});
    let mut stream = UnixStream::connect(&service.socket).unwrap();
    writeln!(stream, "{request}").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let response: Value = serde_json::from_str(&response).unwrap();
    assert!(
        response.get("error").is_some(),
        "packaged inline directive injection was accepted"
    );
    assert!(
        ok(&service, &["connection", "list"])
            .as_array()
            .unwrap()
            .is_empty()
    );
}
