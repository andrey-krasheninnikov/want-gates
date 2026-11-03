mod common;
use common::{Service, status};
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
    assert!(output.stderr.is_empty());
    serde_json::from_slice::<Value>(&output.stdout).unwrap()["data"].clone()
}

#[test]
fn groups_have_stable_ids_and_survive_restart() {
    let mut service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Acme"]);
    let id = group["id"].as_str().unwrap();
    let renamed = ok(&service, &["group", "update", id, "--name", "Company"]);
    assert_eq!(renamed["id"], id);
    assert_eq!(renamed["name"], "Company");
    assert!(service.stop().success());
    service.child = Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(["serve", "--socket"])
        .arg(&service.socket)
        .arg("--state-dir")
        .arg(&service.state)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !status(&service.socket).status.success() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(ok(&service, &["group", "show", id]), renamed);
    assert_eq!(
        ok(&service, &["group", "list"]),
        serde_json::json!([renamed])
    );
    ok(&service, &["group", "delete", id]);
    assert_eq!(ok(&service, &["group", "list"]), serde_json::json!([]));
}

#[test]
fn importing_a_profile_keeps_secrets_separate_and_protects_group_references() {
    let service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Acme"]);
    let group_id = group["id"].as_str().unwrap();
    let profile = service.directory.path().join("profile.json");
    let input = serde_json::json!({"protocol":"vless","settings":{"address":"vpn.example.com","port":443,
        "id":"0e87c4e2-5613-475c-af72-15c56fca5324","encryption":"none","flow":"xtls-rprx-vision"},
        "streamSettings":{"network":"raw","security":"tls","tlsSettings":{"serverName":"vpn.example.com","fingerprint":"chrome"}}});
    std::fs::write(&profile, input.to_string()).unwrap();
    let connection = ok(
        &service,
        &[
            "connection",
            "import",
            "--group",
            group_id,
            "--name",
            "Primary",
            "--protocol",
            "vless",
            "--file",
            profile.to_str().unwrap(),
        ],
    );
    assert_eq!(connection["validation"], "structural");
    assert_eq!(connection["runtime"], "unavailable");
    assert!(!connection.to_string().contains("0e87c4e2"));
    assert!(
        !std::fs::read_to_string(service.state.join("config.json"))
            .unwrap()
            .contains("0e87c4e2")
    );
    let files: Vec<_> = std::fs::read_dir(service.state.join("secrets"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&files[0]).unwrap()).unwrap(),
        input
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(service.state.join("secrets"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let refused = call(&service, &["group", "delete", group_id]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("referenced"));
    let id = connection["id"].as_str().unwrap();
    ok(&service, &["connection", "delete", id]);
    assert_eq!(
        std::fs::read_dir(service.state.join("secrets"))
            .unwrap()
            .count(),
        0
    );
    ok(&service, &["group", "delete", group_id]);
}

fn import_text(service: &Service, group: &str, name: &str, input: &str) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args([
            "connection",
            "import",
            "--group",
            group,
            "--name",
            name,
            "--protocol",
            "vless",
            "--file",
            "-",
            "--socket",
        ])
        .arg(&service.socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn saved_profiles(service: &Service) -> Vec<Value> {
    std::fs::read_dir(service.state.join("secrets"))
        .unwrap()
        .map(|e| serde_json::from_slice(&std::fs::read(e.unwrap().path()).unwrap()).unwrap())
        .collect()
}

#[test]
fn vless_uri_preserves_extended_tls_and_kcp_settings() {
    let service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Examples"]);
    let group = group["id"].as_str().unwrap();
    let output = import_text(
        &service,
        group,
        "TLS",
        "vless://test-id@[2001:db8::1]:443?type=ws&security=tls&host=front.example&path=%2Fvpn%3Fkey%3Dtest%2Bvalue&pcs=test-pin&vcn=server.example&ech=test-ech&alpn=h2%2Chttp%2F1.1#Example",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let profiles = saved_profiles(&service);
    assert_eq!(profiles[0]["settings"]["address"], "2001:db8::1");
    let stream = &profiles[0]["streamSettings"];
    assert_eq!(stream["wsSettings"]["path"], "/vpn?key=test+value");
    assert_eq!(stream["tlsSettings"]["pinnedPeerCertSha256"], "test-pin");
    assert_eq!(
        stream["tlsSettings"]["verifyPeerCertByName"],
        "server.example"
    );
    assert_eq!(
        stream["tlsSettings"]["alpn"],
        serde_json::json!(["h2", "http/1.1"])
    );
    let output = import_text(
        &service,
        group,
        "KCP",
        "vless://test-id@127.0.0.1:443?type=kcp&seed=test-secret&mtu=1350&tti=20&headerType=wireguard&encryption=mlkem768x25519plus.native.0rtt.test",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let profiles = saved_profiles(&service);
    assert!(
        profiles
            .iter()
            .any(|p| p["streamSettings"]["kcpSettings"]["mtu"] == 1350
                && p["settings"]["encryption"] == "mlkem768x25519plus.native.0rtt.test")
    );
}

fn rpc(service: &Service, request: Value) -> Value {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(&service.socket).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    writeln!(stream, "{request}").unwrap();
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    serde_json::from_str(&response).unwrap()
}

#[test]
fn invalid_profiles_and_unavailable_adapters_do_not_change_saved_state() {
    let service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Company"]);
    let group = group["id"].as_str().unwrap();
    let before = std::fs::read(service.state.join("config.json")).unwrap();
    for input in [
        "vless://secret-id@server:0",
        "vless://secret-id@server:443?type=tcp&type=ws",
        "vless://secret-id@server:443?unknown=secret-value",
        "vless://secret-id@server:443?path=%ZZ",
        "vless://secret-id@server:443?security=tls&pbk=secret-value",
        r#"{"protocol":"vless","protocol":"trojan","settings":{}}"#,
        r#"{"protocol":"vless","settings":{"address":"server","port":65536,"id":"secret-id","encryption":"none"}}"#,
        r#"{"protocol":"vless","settings":{"address":"server","port":443,"id":"secret-id"}}"#,
        r#"{"protocol":"vless","settings":{"vnext":[]}}"#,
    ] {
        let output = import_text(&service, group, "Invalid", input);
        assert!(!output.status.success(), "accepted {input}");
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!error.contains("secret-id") && !error.contains("secret-value"));
        assert_eq!(
            std::fs::read(service.state.join("config.json")).unwrap(),
            before
        );
    }
    let refused = rpc(
        &service,
        serde_json::json!({"api_version":1,"command":"connection.import",
        "group_id":group,"name":"Native","protocol":"forti","profile":"secret-value"}),
    );
    assert!(refused["error"].as_str().unwrap().contains("unavailable"));
    assert_eq!(ok(&service, &["connection", "list"]), serde_json::json!([]));
    assert!(!service.state.join("secrets").exists());
}

#[test]
fn connections_move_and_keep_extended_outbound_settings_after_restart() {
    let mut service = Service::start();
    let a = ok(&service, &["group", "create", "--name", "Zeta"]);
    let b = ok(&service, &["group", "create", "--name", "Alpha"]);
    let input = serde_json::json!({"protocol":"vless","settings":{"vnext":[{"address":"vpn.example","port":443,"users":[{
        "id":"test-user","encryption":"mlkem768x25519plus.native.0rtt.test","flow":"xtls-rprx-vision","level":2}]}]},
        "streamSettings":{"network":"xhttp","security":"reality","xhttpSettings":{"path":"/vpn","extra":{"scMaxEachPostBytes":1000000}},
        "realitySettings":{"password":"test-private-value","fingerprint":"chrome","shortId":"abcdef"},"finalmask":{"tcp":[]}},"mux":{"enabled":false}});
    let output = import_text(
        &service,
        a["id"].as_str().unwrap(),
        "Zebra",
        &input.to_string(),
    );
    assert!(output.status.success());
    let connection: Value =
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["data"].clone();
    let id = connection["id"].as_str().unwrap();
    let moved = ok(
        &service,
        &[
            "connection",
            "update",
            id,
            "--name",
            "Renamed",
            "--group",
            b["id"].as_str().unwrap(),
        ],
    );
    assert_eq!(moved["id"], id);
    assert_eq!(moved["group_id"], b["id"]);
    ok(&service, &["group", "delete", a["id"].as_str().unwrap()]);
    assert!(service.stop().success());
    service.child = Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(["serve", "--socket"])
        .arg(&service.socket)
        .arg("--state-dir")
        .arg(&service.state)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !status(&service.socket).status.success() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(ok(&service, &["connection", "show", id]), moved);
    assert_eq!(saved_profiles(&service), vec![input]);
    let replacement = service.directory.path().join("replace.txt");
    std::fs::write(&replacement, "vless://new-test-id@127.0.0.1:443").unwrap();
    let updated = ok(
        &service,
        &[
            "connection",
            "update",
            id,
            "--file",
            replacement.to_str().unwrap(),
        ],
    );
    assert_eq!(updated["id"], id);
    let profiles = saved_profiles(&service);
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0]["settings"]["id"], "new-test-id");
}

#[test]
fn parallel_writes_keep_objects_and_stale_revisions_fail() {
    let service = Service::start();
    std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..12)
            .map(|n| {
                let service = &service;
                scope.spawn(move || {
                    ok(
                        service,
                        &["group", "create", "--name", &format!("Company {n}")],
                    )
                })
            })
            .collect();
        for task in tasks {
            task.join().unwrap();
        }
    });
    let groups = ok(&service, &["group", "list"]);
    assert_eq!(groups.as_array().unwrap().len(), 12);
    let original = &groups[0];
    let id = original["id"].as_str().unwrap();
    let request = serde_json::json!({"api_version":1,"command":"group.update","id":id,"name":"Updated","expected_revision":original["revision"]});
    let first = rpc(&service, request.clone());
    assert!(first.get("error").is_none());
    let stale = rpc(&service, request);
    assert!(
        stale["error"]
            .as_str()
            .unwrap()
            .contains("revision conflict")
    );
    assert_eq!(ok(&service, &["group", "show", id])["name"], "Updated");
    assert_eq!(
        ok(&service, &["group", "list"]).as_array().unwrap().len(),
        12
    );
}

#[test]
fn lists_cross_page_boundaries_and_connection_sorting_uses_group_names() {
    let service = Service::start();
    for n in (0..103).rev() {
        ok(
            &service,
            &["group", "create", "--name", &format!("Company {n:03}")],
        );
    }
    let groups = ok(&service, &["group", "list"]);
    let groups = groups.as_array().unwrap();
    assert_eq!(groups.len(), 103);
    assert_eq!(groups[0]["name"], "Company 000");
    assert_eq!(groups[102]["name"], "Company 102");
    for (group, name) in [(&groups[102], "A"), (&groups[0], "Z"), (&groups[0], "B")] {
        assert!(
            import_text(
                &service,
                group["id"].as_str().unwrap(),
                name,
                "vless://test@127.0.0.1:443"
            )
            .status
            .success()
        );
    }
    let names = |value: Value| {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["name"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(ok(&service, &["connection", "list"])),
        vec!["B", "Z", "A"]
    );
    assert_eq!(
        names(ok(&service, &["connection", "list", "--sort", "name"])),
        vec!["A", "B", "Z"]
    );
    assert_eq!(
        names(ok(
            &service,
            &[
                "connection",
                "list",
                "--group",
                groups[0]["id"].as_str().unwrap()
            ]
        )),
        vec!["B", "Z"]
    );
    let stale = rpc(
        &service,
        serde_json::json!({"api_version":1,"command":"group.list","offset":100,"list_revision":1}),
    );
    assert!(
        stale["error"]
            .as_str()
            .unwrap()
            .contains("changed during listing")
    );
}

#[test]
fn failed_config_write_does_not_publish_or_leave_a_new_profile() {
    use std::os::unix::fs::PermissionsExt;
    let service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Company"]);
    let path = service.state.join("config.json");
    let before = std::fs::read(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    let output = import_text(
        &service,
        group["id"].as_str().unwrap(),
        "Profile",
        "vless://test@127.0.0.1:443",
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(saved_profiles(&service).is_empty());
    assert_eq!(ok(&service, &["connection", "list"]), serde_json::json!([]));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        import_text(
            &service,
            group["id"].as_str().unwrap(),
            "Profile",
            "vless://test@127.0.0.1:443"
        )
        .status
        .success()
    );
}

#[test]
fn a_second_socket_cannot_bypass_the_state_lock() {
    let service = Service::start();
    let second = service.directory.path().join("runtime/other.sock");
    let output = Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(["serve", "--socket"])
        .arg(&second)
        .arg("--state-dir")
        .arg(&service.state)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!second.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already in use"));
    assert!(status(&service.socket).status.success());
}

#[test]
fn corrupt_state_is_retained_and_startup_fails_closed() {
    let mut service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Company"]);
    assert!(service.stop().success());
    let path = service.state.join("config.json");
    let valid = std::fs::read(&path).unwrap();
    for bytes in [b"invalid JSON".to_vec(), {
        let mut config: Value = serde_json::from_slice(&valid).unwrap();
        config["groups"][0]["id"] = serde_json::json!("g9999");
        config.to_string().into_bytes()
    }] {
        std::fs::write(&path, &bytes).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_wgates"))
            .args(["serve", "--socket"])
            .arg(&service.socket)
            .arg("--state-dir")
            .arg(&service.state)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let exited = loop {
            if let Some(exit) = child.try_wait().unwrap() {
                break Some(exit);
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(
            exited.is_some_and(|s| !s.success()),
            "invalid group ID from {:?} was accepted",
            group["id"]
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(!service.socket.exists());
    }
}

fn restart(service: &mut Service) {
    service.child = Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(["serve", "--socket"])
        .arg(&service.socket)
        .arg("--state-dir")
        .arg(&service.state)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !status(&service.socket).status.success() {
        assert!(
            service.child.try_wait().unwrap().is_none(),
            "service exited"
        );
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn rejected_start(service: &Service) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(["serve", "--socket"])
        .arg(&service.socket)
        .arg("--state-dir")
        .arg(&service.state)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if let Some(exit) = child.try_wait().unwrap() {
            assert!(!exit.success());
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("unsafe state accepted");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!service.socket.exists());
}

#[test]
fn profile_security_and_orphan_recovery_preserve_current_data() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let mut service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Company"]);
    assert!(
        import_text(
            &service,
            group["id"].as_str().unwrap(),
            "VPN",
            "vless://test@127.0.0.1:443"
        )
        .status
        .success()
    );
    let config = std::fs::read(service.state.join("config.json")).unwrap();
    let secrets = service.state.join("secrets");
    let profile = std::fs::read_dir(&secrets)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let original = std::fs::read(&profile).unwrap();
    assert!(service.stop().success());
    std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o644)).unwrap();
    rejected_start(&service);
    assert_eq!(std::fs::read(&profile).unwrap(), original);
    std::fs::remove_file(&profile).unwrap();
    rejected_start(&service);
    let outside = service.directory.path().join("outside.json");
    std::fs::write(&outside, &original).unwrap();
    symlink(&outside, &profile).unwrap();
    rejected_start(&service);
    assert_eq!(std::fs::read(&outside).unwrap(), original);
    std::fs::remove_file(&profile).unwrap();
    std::fs::write(&profile, &original).unwrap();
    std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o600)).unwrap();
    let orphan = secrets.join("c999-r999.json");
    std::fs::write(&orphan, &original).unwrap();
    std::fs::set_permissions(&orphan, std::fs::Permissions::from_mode(0o600)).unwrap();
    let unknown = secrets.join("keep.txt");
    std::fs::write(&unknown, "retained").unwrap();
    restart(&mut service);
    assert!(!orphan.exists());
    assert_eq!(std::fs::read_to_string(&unknown).unwrap(), "retained");
    assert_eq!(
        std::fs::read(service.state.join("config.json")).unwrap(),
        config
    );
    assert_eq!(
        ok(&service, &["connection", "list"])
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn input_size_limits_and_duplicate_names_fail_without_partial_state() {
    let service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Company"]);
    let group_id = group["id"].as_str().unwrap();
    assert!(
        !call(&service, &["group", "create", "--name", "Company"])
            .status
            .success()
    );
    assert!(
        !call(&service, &["group", "create", "--name", " "])
            .status
            .success()
    );
    let before = std::fs::read(service.state.join("config.json")).unwrap();
    let output = import_text(&service, group_id, "Large", &"x".repeat(1024 * 1024 + 1));
    assert!(!output.status.success());
    assert_eq!(
        std::fs::read(service.state.join("config.json")).unwrap(),
        before
    );
    let input = serde_json::json!({"protocol":"vless","settings":{"address":"127.0.0.1","port":443,"id":"test","encryption":"none"},
        "streamSettings":{"network":"xhttp","xhttpSettings":{"extra":{"data":"a".repeat(8192)}}}});
    assert!(
        import_text(&service, group_id, "Large", &input.to_string())
            .status
            .success()
    );
    assert!(
        !import_text(&service, group_id, "Large", "vless://test@127.0.0.1:443")
            .status
            .success()
    );
    assert_eq!(saved_profiles(&service), vec![input]);
}

#[test]
fn a_valid_profile_at_the_source_limit_fits_the_import_frame() {
    let service = Service::start();
    let group = ok(&service, &["group", "create", "--name", "Boundary"]);
    let mut source = r#"{"protocol":"vless","settings":{"address":"127.0.0.1","port":443,"id":"example","encryption":"none"}}"#.to_owned();
    source.extend(std::iter::repeat_n('\n', 1024 * 1024 - source.len()));
    assert_eq!(source.len(), 1024 * 1024);
    let output = import_text(&service, group["id"].as_str().unwrap(), "Boundary", &source);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        ok(&service, &["connection", "list"])
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
