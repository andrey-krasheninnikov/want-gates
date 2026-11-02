mod common;
use common::Service;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use std::thread;
use std::time::Duration;

struct Panel {
    url: String,
    template: Arc<Mutex<Value>>,
    writes: Arc<Mutex<usize>>,
    stop: Arc<AtomicBool>,
    failure: Arc<AtomicU8>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Panel {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let template = Arc::new(Mutex::new(
            json!({"log":{"loglevel":"warning"},"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","inboundTag":["api"],"outboundTag":"api"}]}}),
        ));
        let writes = Arc::new(Mutex::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(AtomicU8::new(0));
        let mode = failure.clone();
        let (saved, count, stopping) = (template.clone(), writes.clone(), stop.clone());
        let thread = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(c) => c,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut b = [0; 4096];
                let mut length = None;
                loop {
                    let n = stream.read(&mut b).unwrap();
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&b[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let h = String::from_utf8_lossy(&bytes[..end]);
                        let body = h
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .and_then(|v| v.parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        length = Some(end + 4 + body);
                    }
                    if length.is_some_and(|n| bytes.len() >= n) {
                        break;
                    }
                }
                let request = String::from_utf8(bytes).unwrap();
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer private-panel-token")
                );
                let path = request.split_whitespace().nth(1).unwrap();
                let mut success = true;
                let mut disconnect = false;
                let obj = match path {
                    "/panel/api/server/status" => {
                        json!({"panelVersion":"3.8.5","xray":{"state":"running","version":"26.9.9","errorMsg":""}})
                    }
                    "/panel/api/xray/" => {
                        json!({"xraySetting":saved.lock().unwrap().clone(),"outboundTestUrl":"https://example.org/check"})
                    }
                    "/panel/api/inbounds/list" => {
                        json!([{"id":1,"enable":true,"protocol":"vless","tag":"ingress","nodeId":null,"sniffing":"{\"enabled\":false}"}])
                    }
                    "/panel/api/xray/update" => {
                        let body = request.split_once("\r\n\r\n").unwrap().1;
                        let params: std::collections::HashMap<_, _> =
                            url::form_urlencoded::parse(body.as_bytes())
                                .into_owned()
                                .collect();
                        assert_eq!(params["outboundTestUrl"], "https://example.org/check");
                        *saved.lock().unwrap() =
                            serde_json::from_str(&params["xraySetting"]).unwrap();
                        *count.lock().unwrap() += 1;
                        match mode.swap(0, Ordering::SeqCst) {
                            1 => success = false,
                            2 => {
                                success = false;
                                saved.lock().unwrap()["log"]["intervening"] = json!("retain");
                            }
                            3 => disconnect = true,
                            4 => thread::sleep(Duration::from_millis(1500)),
                            _ => {}
                        }
                        Value::Null
                    }
                    "/panel/api/xray/routeTest" => {
                        let body = request.split_once("\r\n\r\n").unwrap().1;
                        let params: std::collections::HashMap<_, _> =
                            url::form_urlencoded::parse(body.as_bytes())
                                .into_owned()
                                .collect();
                        json!({"outboundTag":if params["ip"].starts_with("10.40."){"wgates-block"}else{"wgates-direct"}})
                    }
                    _ => panic!("unexpected API {path}"),
                };
                if disconnect {
                    continue;
                }
                let body = json!({"success":success,"obj":obj}).to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
        });
        Self {
            url,
            template,
            writes,
            stop,
            failure,
            thread: Some(thread),
        }
    }
}
impl Drop for Panel {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let result = t.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }
}
fn command(s: &Service, args: &[&str], input: Option<&str>) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(args)
        .arg("--socket")
        .arg(&s.socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(v) = input {
        c.stdin.take().unwrap().write_all(v.as_bytes()).unwrap();
    }
    drop(c.stdin.take());
    c.wait_with_output().unwrap()
}
fn ok(s: &Service, args: &[&str], input: Option<&str>) -> Value {
    let r = command(s, args, input);
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    serde_json::from_slice(&r.stdout).unwrap()
}
#[test]
fn preview_is_private_and_apply_rejects_panel_drift() {
    let s = Service::start();
    let p = Panel::start();
    let result = ok(
        &s,
        &["panel", "configure", "--file", "-"],
        Some(&json!({"url":p.url,"token":"private-panel-token"}).to_string()),
    );
    assert!(!result.to_string().contains("private-panel-token"));
    assert_eq!(
        ok(&s, &["panel", "preflight"], None)["data"]["panel_version"],
        "3.8.5"
    );
    let before = p.template.lock().unwrap().clone();
    let preview = ok(&s, &["routing", "preview"], None);
    assert_eq!(*p.writes.lock().unwrap(), 0);
    assert_eq!(*p.template.lock().unwrap(), before);
    assert!(!preview.to_string().contains("private-panel-token"));
    p.template.lock().unwrap()["log"]["loglevel"] = json!("error");
    let result = command(
        &s,
        &[
            "routing",
            "apply",
            preview["data"]["plan_id"].as_str().unwrap(),
        ],
        None,
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("drift"));
    assert_eq!(*p.writes.lock().unwrap(), 0);
}

#[test]
fn apply_preserves_unrelated_settings_and_blocks_unverified_traffic() {
    let s = Service::start();
    let p = Panel::start();
    ok(
        &s,
        &["panel", "configure", "--file", "-"],
        Some(&json!({"url":p.url,"token":"private-panel-token"}).to_string()),
    );
    let g = ok(&s, &["group", "create", "--name", "Company"], None)["data"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        &s,
        &[
            "rule",
            "create",
            "--group",
            &g,
            "--destination",
            "10.40.0.0/24",
        ],
        None,
    );
    let preview = ok(&s, &["routing", "preview"], None);
    let plan = preview["data"]["plan_id"].as_str().unwrap();
    let applied = ok(&s, &["routing", "apply", plan], None);
    assert_eq!(applied["data"]["state"], "blocked");
    assert_eq!(
        p.template.lock().unwrap()["log"],
        json!({"loglevel":"warning"})
    );
    assert_eq!(
        p.template.lock().unwrap()["outbounds"][0],
        json!({"tag":"direct","protocol":"freedom"})
    );
    let count = *p.writes.lock().unwrap();
    ok(&s, &["routing", "apply", plan], None);
    assert_eq!(*p.writes.lock().unwrap(), count);
}

fn configured_rule(s: &Service, p: &Panel) -> (String, String) {
    ok(
        s,
        &["panel", "configure", "--file", "-"],
        Some(&json!({"url":p.url,"token":"private-panel-token"}).to_string()),
    );
    let g = ok(s, &["group", "create", "--name", "Company"], None)["data"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let r = ok(
        s,
        &[
            "rule",
            "create",
            "--group",
            &g,
            "--destination",
            "10.40.0.0/24",
        ],
        None,
    )["data"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let preview = ok(s, &["routing", "preview"], None);
    ok(
        s,
        &[
            "routing",
            "apply",
            preview["data"]["plan_id"].as_str().unwrap(),
        ],
        None,
    );
    (g, r)
}
#[test]
fn failed_acknowledgement_and_lost_response_restore_the_verified_snapshot() {
    for mode in [1, 3] {
        let s = Service::start();
        let p = Panel::start();
        let (_, rule) = configured_rule(&s, &p);
        let base = p.template.lock().unwrap().clone();
        ok(
            &s,
            &["rule", "update", &rule, "--destination", "10.40.1.0/24"],
            None,
        );
        let preview = ok(&s, &["routing", "preview"], None);
        let id = preview["data"]["plan_id"].as_str().unwrap();
        p.failure.store(mode, Ordering::SeqCst);
        assert!(
            !command(&s, &["routing", "apply", id], None)
                .status
                .success()
        );
        assert_eq!(*p.template.lock().unwrap(), base);
        assert_eq!(
            ok(&s, &["routing", "status"], None)["data"]["last_observation"]["state"],
            "restored"
        );
    }
}
#[test]
fn intervening_edit_prevents_restore_and_new_preview_until_reconciled() {
    let s = Service::start();
    let p = Panel::start();
    let (_, rule) = configured_rule(&s, &p);
    let base = p.template.lock().unwrap().clone();
    ok(
        &s,
        &["rule", "update", &rule, "--destination", "10.40.1.0/24"],
        None,
    );
    let preview = ok(&s, &["routing", "preview"], None);
    let id = preview["data"]["plan_id"].as_str().unwrap();
    p.failure.store(2, Ordering::SeqCst);
    let count = *p.writes.lock().unwrap();
    assert!(
        !command(&s, &["routing", "apply", id], None)
            .status
            .success()
    );
    assert_eq!(*p.writes.lock().unwrap(), count + 1);
    assert_eq!(p.template.lock().unwrap()["log"]["intervening"], "retain");
    assert_eq!(
        ok(&s, &["routing", "status"], None)["data"]["last_observation"]["state"],
        "recovery_required"
    );
    assert!(!command(&s, &["routing", "preview"], None).status.success());
    assert!(
        !command(&s, &["routing", "recover", id], None)
            .status
            .success()
    );
    assert_eq!(*p.writes.lock().unwrap(), count + 1);
    *p.template.lock().unwrap() = base;
    assert_eq!(
        ok(&s, &["routing", "recover", id], None)["data"]["state"],
        "restored"
    );
}

fn start_apply(s: &Service, id: &str) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(["routing", "apply", id, "--socket"])
        .arg(&s.socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}
fn wait_for_write(p: &Panel, previous: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while *p.writes.lock().unwrap() == previous {
        assert!(std::time::Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn readiness_and_status_remain_responsive_while_apply_blocks_external_writes() {
    let s = Service::start();
    let p = Panel::start();
    let (_, rule) = configured_rule(&s, &p);
    ok(
        &s,
        &["rule", "update", &rule, "--destination", "10.40.1.0/24"],
        None,
    );
    let preview = ok(&s, &["routing", "preview"], None);
    let id = preview["data"]["plan_id"].as_str().unwrap();
    p.failure.store(4, Ordering::SeqCst);
    let count = *p.writes.lock().unwrap();
    let child = start_apply(&s, id);
    wait_for_write(&p, count);
    let started = std::time::Instant::now();
    assert!(common::status(&s.socket).status.success());
    assert_eq!(ok(&s, &["routing", "status"], None)["data"]["busy"], true);
    assert!(
        !command(&s, &["group", "create", "--name", "Busy"], None)
            .status
            .success()
    );
    assert!(started.elapsed() < Duration::from_millis(900));
    assert!(child.wait_with_output().unwrap().status.success());
}
#[test]
fn interrupted_apply_requires_reconciliation_after_service_restart() {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let mut s = Service::start();
    let p = Panel::start();
    let (_, rule) = configured_rule(&s, &p);
    let base = p.template.lock().unwrap().clone();
    ok(
        &s,
        &["rule", "update", &rule, "--destination", "10.40.1.0/24"],
        None,
    );
    let preview = ok(&s, &["routing", "preview"], None);
    let id = preview["data"]["plan_id"].as_str().unwrap();
    let metadata = std::fs::symlink_metadata(&s.socket).unwrap();
    p.failure.store(4, Ordering::SeqCst);
    let count = *p.writes.lock().unwrap();
    let child = start_apply(&s, id);
    wait_for_write(&p, count);
    s.child.kill().unwrap();
    s.child.wait().unwrap();
    assert!(!child.wait_with_output().unwrap().status.success());
    let current = std::fs::symlink_metadata(&s.socket).unwrap();
    assert!(current.file_type().is_socket());
    assert_eq!(
        (current.dev(), current.ino()),
        (metadata.dev(), metadata.ino())
    );
    std::fs::remove_file(&s.socket).unwrap();
    s.start_again();
    let status = ok(&s, &["routing", "status"], None);
    assert_eq!(status["data"]["busy"], false);
    assert_eq!(status["data"]["recovery_required"], true);
    assert!(!command(&s, &["routing", "preview"], None).status.success());
    assert_eq!(
        ok(&s, &["routing", "recover", id], None)["data"]["state"],
        "restored"
    );
    assert_eq!(*p.template.lock().unwrap(), base);
}
