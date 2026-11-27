"""Exercise authorized panel edits, explicit apply, and live VLESS routing."""

import argparse
import json
import secrets

from panel_status_smoke import login, request, status
from routing_smoke import main, run


def acceptance(stand):
    root = "/panel/api/want-gates/operations/"
    csrf = login(stand)
    token = request(stand, "/panel/csrf-token", headers=csrf)
    assert token["status"] == 200 and token["data"]["success"]
    headers = {
        **csrf, "X-CSRF-Token": token["data"]["obj"], "Content-Type": "application/json",
    }

    def operation(command, payload=None, expected=200):
        reply = request(stand, root + command, {} if payload is None else payload, headers)
        assert reply["status"] == expected, (command, reply["status"])
        assert reply["cache_control"] == "no-store"
        if expected == 200:
            assert reply["data"]["success"], command
            return reply["data"]["obj"]
        assert not reply["data"]["success"], command
        return reply["data"]["msg"]

    def peer():
        marker = "/route-" + secrets.token_hex(8)
        result = run(
            "ip", "netns", "exec", stand["names"]["client"], "curl", "--noproxy", "", "--socks5-hostname", "127.0.0.1:10880",
            "--max-time", "5", "-fsS", "http://10.220.0.10:18080" + marker,
        )
        return json.loads(result.stdout)["peer"] if result.returncode == 0 else None

    before = peer()

    assert request(stand, root + "group.create", {"name": "Unauthorized"}, {"Content-Type": "application/json"})["status"] == 401
    assert request(stand, root + "group.create", {"name": "Without CSRF"}, {**csrf, "Content-Type": "application/json"})["status"] == 403
    assert request(stand, root + "group.create", {"name": "Bearer only"}, {
        "Content-Type": "application/json", "Authorization": "Bearer " + stand["panel_token"],
    })["status"] == 401
    operation("panel.configure", {}, 404)
    operation("group.create", {"name": "Browser managed", "command": "panel.configure"}, 400)
    operation("group.create", {"name": "Browser managed"})
    groups = status(stand, csrf)["groups"]
    assert len(groups) == 1 and groups[0]["name"] == "Browser managed"
    group = groups[0]

    operation("connection.import", {
        "group_id": group["id"], "name": "Managed VLESS", "protocol": "vless",
        "profile": json.dumps(stand["outbound"]("10.213.0.2", 19001, stand["ids"]["a"])),
        "allowed_capabilities": ["tcp_ipv4"],
    })
    connection = status(stand, csrf)["connections"][0]
    operation("group.update", {
        "id": group["id"], "expected_revision": group["revision"],
        "primary": connection["id"], "probes": {
            "tcp_ipv4": {"url": "http://10.220.0.10:18080/panel-managed"},
        },
    })
    operation("rule.create", {"group_id": group["id"], "destination": "10.220.0.0/24"})
    desired = status(stand, csrf)
    assert desired["routing"]["last_observation"]["running_revision"] is None
    assert desired["connections"][0]["runtime"] == "unavailable"
    assert stand["ids"]["a"] not in json.dumps(desired)

    assert peer() == before, "saving changed live routing"
    preview = operation("routing.preview")
    assert preview["base_revision"] is None
    assert any(change["before"] is None and change["kind"] == "rule" for change in preview["changes"])
    assert preview["desired_revision"] == desired["routing"]["desired_revision"]
    assert preview["rules"][0]["destination"] == "10.220.0.0/24"
    assert peer() == before, "preview changed live routing"
    applied = operation("routing.apply", {"plan_id": preview["plan_id"]})
    assert applied["state"] in ("partial", "applied")
    assert applied["running_revision"] == preview["desired_revision"] and not applied["mismatch"]
    assert peer() == "10.211.0.1", "traffic did not cross the selected VLESS exit"
    live = status(stand, csrf)
    assert live["groups"][0]["last_observed_selection"]["id"] == connection["id"]
    assert live["connections"][0]["verification"]["capabilities"]["tcp_ipv4"]["state"] == "verified"

    group = live["groups"][0]
    operation("group.delete", {"id": group["id"], "expected_revision": group["revision"]}, 409)
    operation("group.update", {
        "id": group["id"], "expected_revision": group["revision"], "name": "Edited group",
        "healthcheck": {
            "target": "http://10.220.0.10:18080/panel-managed",
            "required_capabilities": ["tcp_ipv4"], "expected_status": 204,
        },
        "probes": {"tcp_ipv4": {"url": "http://10.220.0.10:18080/updated-probe"}},
    })
    operation("group.update", {
        "id": group["id"], "expected_revision": group["revision"], "name": "Stale edit",
    }, 409)
    operation("connection.delete", {
        "id": connection["id"], "expected_revision": live["connections"][0]["revision"],
    }, 409)
    operation("connection.update", {
        "id": connection["id"], "expected_revision": live["connections"][0]["revision"],
        "name": "Edited connection", "dns": "udp://10.220.0.53:53",
        "profile": json.dumps(stand["outbound"]("10.214.0.2", 19002, stand["ids"]["b"])),
    })
    edited = status(stand, csrf)
    assert edited["connections"][0]["name"] == "Edited connection"
    assert edited["connections"][0]["dns"] == "udp://10.220.0.53:53"
    operation("rule.create", {"group_id": group["id"], "destination": "203.0.113.11/32"})
    rule = next(rule for rule in status(stand, csrf)["rules"] if rule["destination"].startswith("203.0.113.11"))
    for destination in ("corp.example", "full:corp.example"):
        operation("rule.update", {
            "id": rule["id"], "expected_revision": rule["revision"],
            "group_id": group["id"], "destination": destination,
        })
        rule = next(rule for rule in status(stand, csrf)["rules"] if rule["destination"] == destination)
    operation("rule.delete", {"id": rule["id"], "expected_revision": rule["revision"]})
    pending = status(stand, csrf)["routing"]
    assert pending["desired_revision"] != pending["last_observation"]["running_revision"]
    assert peer() == "10.211.0.1"
    applied_rule = live["rules"][0]
    operation("rule.delete", {"id": applied_rule["id"], "expected_revision": applied_rule["revision"]})
    preview = operation("routing.preview")
    assert preview["base_revision"] == live["routing"]["last_observation"]["running_revision"]
    removed = next(change for change in preview["changes"] if change["id"] == applied_rule["id"])
    assert removed["before"][0] == "10.220.0.0/24" and removed["after"] is None
    changed_group = next(change for change in preview["changes"] if change["id"] == group["id"])
    assert changed_group["before"][0] == "Browser managed"
    assert changed_group["after"][0] == "Edited group"
    assert "Expected HTTP status: 204" in changed_group["after"]
    assert "Transport or DNS verification probes changed" in changed_group["notes"]
    changed_connection = next(change for change in preview["changes"] if change["id"] == connection["id"])
    assert changed_connection["notes"] == ["Connection profile replaced"]
    assert stand["ids"]["b"] not in json.dumps(preview)
    assert peer() == "10.211.0.1"

    settings = stand["api"]("xray/", {})
    if isinstance(settings, str):
        settings = json.loads(settings)
    settings["xraySetting"]["log"]["loglevel"] = "error"
    stand["api"]("xray/update", {
        "xraySetting": json.dumps(settings["xraySetting"]),
        "outboundTestUrl": settings["outboundTestUrl"],
    })
    operation("routing.apply", {"plan_id": preview["plan_id"]}, 409)
    assert peer() == "10.211.0.1"
    print("Panel CSRF, allowlist, desired edits, VLESS packet path, conflicts and drift passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("wgates")
    parser.add_argument("panel_root")
    args = parser.parse_args()
    main(args.wgates, args.panel_root, panel_acceptance=acceptance)
