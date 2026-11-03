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
fn setup(s: &Service, name: &str) -> (String, String) {
    let group = ok(s, &["group", "create", "--name", name], None)["data"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let id = ok(s, &["connection", "import", "--group", &group, "--name", "VPN", "--protocol", "vless", "--file", "-"], Some("vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?encryption=none&security=none"))["data"]["id"].as_str().unwrap().to_owned();
    (group, id)
}
#[test]
fn healthcheck_defaults_references_and_disabled_legacy_groups_survive_restart() {
    let mut s = Service::start();
    let (group, primary) = setup(&s, "Company");
    let initial = ok(&s, &["group", "show", &group], None);
    assert_eq!(initial["data"]["fallbacks"], json!([]));
    assert!(initial["data"]["healthcheck"].is_null());
    let reserve = ok(&s, &["connection", "import", "--group", &group, "--name", "Reserve", "--protocol", "vless", "--file", "-"], Some("vless://00000000-0000-4000-8000-000000000002@127.0.0.1:443?encryption=none&security=none"))["data"]["id"].as_str().unwrap().to_owned();
    let saved = ok(
        &s,
        &[
            "group",
            "update",
            &group,
            "--primary",
            &primary,
            "--fallbacks",
            &reserve,
            "--healthcheck-file",
            "-",
        ],
        Some(
            r#"{"target":"tcp://health.corp.test:22","expect_hex":"5353482d","required_capabilities":["tcp_ipv4"]}"#,
        ),
    );
    let h = &saved["data"]["healthcheck"];
    assert_eq!(h["interval_seconds"], 30);
    assert_eq!(h["timeout_seconds"], 5);
    assert_eq!(h["failure_threshold"], 3);
    assert_eq!(h["recovery_threshold"], 5);
    assert!(
        !run(&s, &["connection", "delete", &reserve], None)
            .status
            .success()
    );
    assert!(s.stop().success());
    s.start_again();
    assert_eq!(ok(&s, &["group", "show", &group], None), saved);
    ok(
        &s,
        &[
            "group",
            "update",
            &group,
            "--fallbacks",
            "-",
            "--healthcheck-file",
            "-",
        ],
        Some("null"),
    );
    ok(&s, &["connection", "delete", &reserve], None);
}
#[test]
fn invalid_group_policy_is_atomic_and_cannot_cross_groups() {
    let s = Service::start();
    let (group, primary) = setup(&s, "A");
    let (_, foreign) = setup(&s, "B");
    ok(
        &s,
        &["group", "update", &group, "--primary", &primary],
        None,
    );
    let before = ok(&s, &["group", "show", &group], None);
    for fallbacks in [&foreign, &primary, "missing"] {
        assert!(
            !run(
                &s,
                &[
                    "group",
                    "update",
                    &group,
                    "--name",
                    "Changed",
                    "--fallbacks",
                    fallbacks
                ],
                None
            )
            .status
            .success()
        );
        assert_eq!(ok(&s, &["group", "show", &group], None), before);
    }
    let base =
        json!({"target":"https://health.corp.test/ready","required_capabilities":["tcp_ipv4"]});
    for (key, value) in [
        ("interval_seconds", json!(0)),
        ("timeout_seconds", json!(61)),
        ("failure_threshold", json!(0)),
        ("recovery_threshold", json!(1001)),
        ("required_capabilities", json!([])),
        ("required_capabilities", json!(["tcp_ipv4", "tcp_ipv4"])),
        ("target", json!("https://user:secret@health.corp.test/")),
        ("target", json!("tcp://health.corp.test")),
        ("ca_pem", json!("not a certificate")),
        ("target", json!("tcp://health.corp.test:22")),
        ("expect_hex", json!("0")),
        ("send_hex", json!("0102")),
    ] {
        let mut value_json = base.clone();
        value_json[key] = value;
        assert!(
            !run(
                &s,
                &["group", "update", &group, "--healthcheck-file", "-"],
                Some(&value_json.to_string())
            )
            .status
            .success(),
            "{key}"
        );
        assert_eq!(ok(&s, &["group", "show", &group], None), before);
    }
}

#[test]
fn saved_groups_without_health_fields_load_without_rewriting_configuration() {
    let mut s = Service::start();
    let (group, _) = setup(&s, "Legacy");
    assert!(s.stop().success());
    let path = s.state.join("config.json");
    let mut saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for group in saved["groups"].as_array_mut().unwrap() {
        let object = group.as_object_mut().unwrap();
        object.remove("healthcheck");
        object.remove("fallbacks");
    }
    let bytes = serde_json::to_vec_pretty(&saved).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    s.start_again();
    let shown = ok(&s, &["group", "show", &group], None);
    assert_eq!(shown["data"]["fallbacks"], json!([]));
    assert!(shown["data"]["healthcheck"].is_null());
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn group_listing_pages_large_ca_metadata_without_losing_objects() {
    let s = Service::start();
    let certificate = include_str!("fixtures/health-ca.pem");
    let mut ca = certificate.repeat((64 * 1024) / certificate.len());
    ca.push_str(&"\n".repeat(64 * 1024 - ca.len()));
    let policy=json!({"target":"https://health.corp.test/ready","required_capabilities":["tcp_ipv4"],"ca_pem":ca}).to_string();
    for index in 0..72 {
        let (group, primary) = setup(&s, &format!("Company {index:02}"));
        ok(
            &s,
            &[
                "group",
                "update",
                &group,
                "--primary",
                &primary,
                "--healthcheck-file",
                "-",
            ],
            Some(&policy),
        );
    }
    let listed = ok(&s, &["group", "list"], None);
    assert_eq!(listed["data"].as_array().unwrap().len(), 72);
    assert_eq!(listed["data"][0]["name"], "Company 00");
    assert_eq!(listed["data"][71]["name"], "Company 71");
}

#[test]
fn tcp_health_requires_bounded_response_bytes_and_validates_messages_atomically() {
    let s = Service::start();
    let (group, primary) = setup(&s, "TCP");
    ok(
        &s,
        &["group", "update", &group, "--primary", &primary],
        None,
    );
    let before = ok(&s, &["group", "show", &group], None);
    let base = json!({"target":"tcp://127.0.0.1:22","required_capabilities":["tcp_ipv4"],"expect_hex":"5353482D"});
    for (field, value) in [
        ("expect_hex", json!(null)),
        ("expect_hex", json!("")),
        ("expect_hex", json!("0")),
        ("expect_hex", json!("gg")),
        ("expect_hex", json!("00".repeat(1025))),
        ("send_hex", json!("xyz")),
        ("send_hex", json!("00".repeat(1025))),
    ] {
        let mut policy = base.clone();
        policy[field] = value;
        assert!(
            !run(
                &s,
                &["group", "update", &group, "--healthcheck-file", "-"],
                Some(&policy.to_string())
            )
            .status
            .success()
        );
        assert_eq!(ok(&s, &["group", "show", &group], None), before);
    }
    let mut policy = base;
    policy["send_hex"] = json!("000Aff");
    let saved = ok(
        &s,
        &["group", "update", &group, "--healthcheck-file", "-"],
        Some(&policy.to_string()),
    );
    assert_eq!(saved["data"]["healthcheck"]["send_hex"], "000Aff");
    assert_eq!(saved["data"]["healthcheck"]["expect_hex"], "5353482D");
}
