mod common;
use common::Service;
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

fn run(service: &Service, args: &[&str], input: Option<&str>) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(args)
        .arg("--socket")
        .arg(&service.socket)
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
fn ok(service: &Service, args: &[&str], input: Option<&str>) -> Value {
    let result = run(service, args, input);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}
#[test]
fn rules_and_primary_keep_references_and_survive_restart() {
    let mut s = Service::start();
    let group = ok(&s, &["group", "create", "--name", "Company"], None)["data"].clone();
    let gid = group["id"].as_str().unwrap();
    let connection=ok(&s,&["connection","import","--group",gid,"--name","VPN","--protocol","vless","--file","-"],Some("vless://00000000-0000-4000-8000-000000000001@127.0.0.1:443?encryption=none&security=none"))["data"].clone();
    let cid = connection["id"].as_str().unwrap();
    let group = ok(&s, &["group", "update", gid, "--primary", cid], None);
    assert_eq!(group["data"]["primary"], cid);
    let rule = ok(
        &s,
        &[
            "rule",
            "create",
            "--group",
            gid,
            "--destination",
            "10.20.30.44/24",
        ],
        None,
    )["data"]
        .clone();
    let rid = rule["id"].as_str().unwrap();
    assert_eq!(rule["destination"], "10.20.30.0/24");
    let duplicate = run(
        &s,
        &[
            "rule",
            "create",
            "--group",
            gid,
            "--destination",
            "10.20.30.1/24",
        ],
        None,
    );
    assert!(!duplicate.status.success());
    assert!(
        !run(&s, &["connection", "delete", cid], None)
            .status
            .success()
    );
    assert!(!run(&s, &["group", "delete", gid], None).status.success());
    let v6 = ok(
        &s,
        &["rule", "create", "--group", gid, "--destination", "fd00::1"],
        None,
    );
    assert_eq!(v6["data"]["destination"], "fd00::1/128");
    assert!(s.stop().success());
    s.start_again();
    assert_eq!(
        ok(&s, &["group", "show", gid], None)["data"]["primary"],
        cid
    );
    assert_eq!(ok(&s, &["rule", "show", rid], None)["data"], rule);
    ok(&s, &["group", "update", gid, "--primary", "-"], None);
    ok(&s, &["connection", "delete", cid], None);
    let result = run(&s, &["group", "delete", gid], None);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("rules"));
    assert_eq!(
        ok(&s, &["rule", "list"], None)["data"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn invalid_rules_and_probe_changes_do_not_save_partial_state() {
    let s = Service::start();
    let group = ok(&s, &["group", "create", "--name", "Company"], None)["data"].clone();
    let id = group["id"].as_str().unwrap();
    for destination in [
        "example.org",
        "10.0.0.1/33",
        "fd00::1/129",
        "::ffff:10.0.0.1",
        "10.0.0.0/-1",
    ] {
        assert!(
            !run(
                &s,
                &[
                    "rule",
                    "create",
                    "--group",
                    id,
                    "--destination",
                    destination
                ],
                None
            )
            .status
            .success()
        );
    }
    assert_eq!(
        ok(&s, &["rule", "list"], None)["data"],
        serde_json::json!([])
    );
    for source in [
        r#"{"tcp_ipv4":{"url":"http://example.org/"}}"#,
        r#"{"tcp_ipv4":{"url":"http://[fd00::1]/"}}"#,
        r#"{"udp_ipv4":{"server":"10.0.0.1:53","query_name":"x.test","query_type":"TXT"}}"#,
        r#"{"future":{}}"#,
        r#"{"tcp_ipv4":{"url":"http://10.0.0.1/?token=secret"}}"#,
    ] {
        assert!(
            !run(
                &s,
                &["group", "update", id, "--probe-file", "-"],
                Some(source)
            )
            .status
            .success()
        );
        assert_eq!(ok(&s, &["group", "show", id], None)["data"], group);
    }
}

#[test]
fn unsafe_routing_directory_is_rejected_without_removing_it() {
    use std::os::unix::fs::symlink;
    let mut service = Service::start();
    assert!(service.stop().success());
    let target = service.directory.path().join("unrelated");
    std::fs::create_dir(&target).unwrap();
    let routing = service.state.join("routing");
    symlink(&target, &routing).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(["serve", "--socket"])
        .arg(&service.socket)
        .arg("--state-dir")
        .arg(&service.state)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("unsafe routing directory was accepted");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(routing.is_symlink());
    assert!(target.is_dir());
}
