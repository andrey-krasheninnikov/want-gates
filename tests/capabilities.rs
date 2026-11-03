mod common;
use common::Service;
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

fn run(s: &Service, args: &[&str], input: Option<&str>) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(args)
        .arg("--socket")
        .arg(&s.socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = input {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    drop(child.stdin.take());
    child.wait_with_output().unwrap()
}
fn ok(s: &Service, args: &[&str], input: Option<&str>) -> Value {
    let result = run(s, args, input);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}
fn connection(s: &Service) -> String {
    let group = ok(s, &["group", "create", "--name", "Company"], None)["data"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(s, &["connection", "import", "--group", &group, "--name", "VPN", "--protocol", "vless", "--file", "-"], Some("vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?encryption=none&security=none"))["data"]["id"].as_str().unwrap().to_owned()
}

#[test]
fn capability_limits_are_explicit_and_survive_restart() {
    let mut s = Service::start();
    let id = connection(&s);
    let all = json!(["tcp_ipv4", "udp_ipv4", "tcp_ipv6", "udp_ipv6"]);
    let initial = ok(&s, &["connection", "show", &id], None);
    assert_eq!(initial["data"]["allowed_capabilities"], all);
    assert_eq!(
        initial["data"]["verification"]["capabilities"]["tcp_ipv4"]["state"],
        "unverified"
    );
    let limited = ok(
        &s,
        &["connection", "update", &id, "--capabilities", "tcp_ipv4"],
        None,
    );
    assert_eq!(limited["data"]["allowed_capabilities"], json!(["tcp_ipv4"]));
    assert_eq!(
        limited["data"]["verification"]["capabilities"]["udp_ipv4"]["reason"],
        "configured_limit"
    );
    assert!(s.stop().success());
    s.start_again();
    assert_eq!(
        ok(&s, &["connection", "show", &id], None)["data"]["allowed_capabilities"],
        json!(["tcp_ipv4"])
    );
    assert_eq!(
        ok(
            &s,
            &["connection", "update", &id, "--capabilities", "all"],
            None
        )["data"]["allowed_capabilities"],
        all
    );
    assert_eq!(
        ok(
            &s,
            &["connection", "update", &id, "--capabilities", "none"],
            None
        )["data"]["allowed_capabilities"],
        json!([])
    );
}

#[test]
fn invalid_capability_updates_leave_the_connection_unchanged() {
    let s = Service::start();
    let id = connection(&s);
    let before = ok(&s, &["connection", "show", &id], None);
    for value in [
        "",
        "tcp",
        "ipv6",
        "tcp_ipv4,tcp_ipv4",
        "TCP_IPV4",
        "all,tcp_ipv4",
        "udp_ipv4, tcp_ipv6",
    ] {
        assert!(
            !run(
                &s,
                &["connection", "update", &id, "--capabilities", value],
                None
            )
            .status
            .success()
        );
        assert_eq!(ok(&s, &["connection", "show", &id], None), before);
    }
}

#[test]
fn configurations_without_limits_keep_their_ids_and_default_to_unverified() {
    let mut s = Service::start();
    let id = connection(&s);
    let before = ok(&s, &["connection", "show", &id], None)["data"].clone();
    assert!(s.stop().success());
    let path = s.state.join("config.json");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    config["connections"][0]
        .as_object_mut()
        .unwrap()
        .remove("allowed_capabilities");
    let bytes = serde_json::to_vec(&config).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    s.start_again();
    assert_eq!(ok(&s, &["connection", "show", &id], None)["data"], before);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}
