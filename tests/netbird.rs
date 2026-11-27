mod common;

use common::Service;
use serde_json::{Value, json};
use std::process::{Command, Output};

fn call(service: &Service, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(args)
        .arg("--socket")
        .arg(&service.socket)
        .output()
        .unwrap()
}

fn data(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice::<Value>(&output.stdout).unwrap()["data"].clone()
}

#[test]
fn netbird_profiles_are_private_and_verified_only_at_runtime() {
    let mut service = Service::start();
    let group = data(call(&service, &["group", "create", "--name", "Office"]));
    let path = service.directory.path().join("netbird.json");
    let import = |service: &Service, name| {
        call(
            service,
            &[
                "connection",
                "import",
                "--group",
                group["id"].as_str().unwrap(),
                "--name",
                name,
                "--protocol",
                "netbird",
                "--file",
                path.to_str().unwrap(),
            ],
        )
    };
    let mut profile = json!({"management_url":"https://management.example.test","mode":"private"});
    for rejected in [
        json!({"management_url":"http://management.example.test","mode":"private"}),
        json!({"management_url":"https://private-marker@management.example.test","mode":"private"}),
        json!({"management_url":"https://management.example.test","mode":"private","setup_key":"private-marker"}),
        json!({"management_url":"https://management.example.test","mode":"exit"}),
        json!({"management_url":"https://management.example.test","mode":"private","exit_network_id":"exit"}),
    ] {
        std::fs::write(&path, rejected.to_string()).unwrap();
        let output = import(&service, "Rejected");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!error.contains("private-marker"));
        if rejected["mode"] == "private" && rejected.get("exit_network_id").is_some() {
            assert!(error.contains("omit exit_network_id in NetBird private mode"));
        }
    }
    std::fs::write(&path, profile.to_string()).unwrap();
    let private = data(import(&service, "Private"));
    profile["mode"] = json!("exit");
    profile["exit_network_id"] = json!("office-exit");
    std::fs::write(&path, profile.to_string()).unwrap();
    let exit = data(import(&service, "Exit"));
    assert!(service.stop().success());
    service.start_again();

    for connection in [private, exit] {
        let id = connection["id"].as_str().unwrap();
        let shown = data(call(&service, &["connection", "show", id]));
        assert_eq!(shown["protocol"], "netbird");
        assert_eq!(shown["authentication"], "not_attempted");
        assert_eq!(shown["capabilities"], json!([]));
        assert!(!shown.to_string().contains("management.example.test"));
        let login = call(&service, &["connection", "login", id]);
        assert!(!login.status.success());
        assert!(
            String::from_utf8_lossy(&login.stderr)
                .contains("requires a current routing preview and apply")
        );
    }
}
