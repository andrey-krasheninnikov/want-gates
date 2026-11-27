"""Exercise the rebuilt panel and local control service in the routing stand."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from routing_smoke import main


def call_panel():
    request = json.load(sys.stdin)
    uri = "http://127.0.0.1:20530" + request["path"]
    headers = {"X-Requested-With": "XMLHttpRequest", **request.get("headers", {})}
    body = request.get("body")
    if body is not None:
        if headers.get("Content-Type") == "application/json":
            body = json.dumps(body).encode()
        else:
            body = urllib.parse.urlencode(body).encode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        result = opener.open(urllib.request.Request(uri, headers=headers, data=body), timeout=320)
    except urllib.error.HTTPError as error:
        result = error
    with result as response:
        text = response.read(8 * 1024 * 1024).decode()
        data = json.loads(text) if response.headers.get_content_type() == "application/json" else text
        print(json.dumps({
            "status": response.code,
            "cache_control": response.headers.get("Cache-Control", ""),
            "cookie": response.headers.get("Set-Cookie", "").partition(";")[0],
            "data": data,
        }))


def request(stand, path, body=None, headers=None):
    result = stand["ns"](
        "gateway", sys.executable, "-B", Path(__file__).absolute(), "--http",
        input=json.dumps({"path": path, "body": body, "headers": headers or {}}),
    )
    return json.loads(result.stdout)


def login(stand):
    csrf = request(stand, "/csrf-token")
    assert csrf["status"] == 200 and csrf["cookie"] and csrf["data"]["success"]
    authorized = request(
        stand,
        "/login",
        stand["panel_login"],
        {"Cookie": csrf["cookie"], "X-CSRF-Token": csrf["data"]["obj"]},
    )
    assert authorized["status"] == 200 and authorized["data"]["success"] and authorized["cookie"]
    return {"Cookie": authorized["cookie"]}


def status(stand, auth):
    response = request(stand, "/panel/api/want-gates/status", headers=auth)
    assert response["status"] == 200 and response["cache_control"] == "no-store"
    assert response["data"]["success"]
    return response["data"]["obj"]


def acceptance(stand):
    route = "/panel/api/want-gates/status"
    assert request(stand, route)["status"] == 401
    denied = request(stand, route, headers={"Authorization": "Bearer " + stand["panel_token"]})
    assert denied["status"] == 401

    auth = login(stand)
    page = request(stand, "/panel/want-gates", headers=auth)
    assert page["status"] == 200 and "<!doctype html>" in page["data"].lower()
    empty = status(stand, auth)
    assert empty["routing"]["last_observation"]["state"] == "unapplied"
    assert all(empty[key] == [] for key in ("groups", "connections", "rules"))

    control = stand["control"]
    group = control("group", "create", "--name", "Company status")["data"]
    connection = control(
        "connection", "import", "--group", group["id"], "--name", "Status VLESS",
        "--protocol", "vless", "--file", "-",
        payload=stand["outbound"]("10.213.0.2", 19001, stand["ids"]["a"]),
    )["data"]
    control(
        "group", "update", group["id"], "--primary", connection["id"], "--probe-file", "-",
        payload={"tcp_ipv4": {"url": "http://10.220.0.10:18080/panel-status"}},
    )
    control("rule", "create", "--group", group["id"], "--destination", "10.220.0.0/24")
    control("group", "update", group["id"], "--healthcheck-file", "-", payload={
        "target": "http://10.220.0.10:18080/panel-health",
        "required_capabilities": ["tcp_ipv4"], "interval_seconds": 3, "timeout_seconds": 2,
    })
    plan = control("routing", "preview")["data"]["plan_id"]
    control("routing", "apply", plan)
    applied = status(stand, auth)
    assert applied["groups"][0]["name"] == "Company status"
    assert applied["connections"][0]["name"] == "Status VLESS"
    assert applied["connections"][0]["verification"]["capabilities"]["tcp_ipv4"]["state"] == "verified"
    assert applied["rules"][0]["destination"] == "10.220.0.0/24"
    assert applied["groups"][0]["last_observed_selection"]["id"] == connection["id"]
    assert applied["routing"]["desired_revision"] == applied["routing"]["last_observation"]["running_revision"]
    assert stand["ids"]["a"] not in json.dumps(applied)
    assert stand["panel_token"] not in json.dumps(applied)

    settings = stand["api"]("xray/", {})
    if isinstance(settings, str):
        settings = json.loads(settings)
    settings["xraySetting"]["log"]["loglevel"] = "error"
    stand["api"]("xray/update", {
        "xraySetting": json.dumps(settings["xraySetting"]),
        "outboundTestUrl": settings["outboundTestUrl"],
    })
    deadline = time.monotonic() + 12
    while True:
        observed = request(stand, route, headers=auth)
        if observed["status"] == 200 and observed["data"]["obj"]["routing"]["health_error"] == "panel_drift":
            applied = observed["data"]["obj"]
            break
        assert time.monotonic() < deadline, "panel did not expose paused health checks"
        time.sleep(0.15)

    control("group", "update", group["id"], "--name", "Saved only")
    saved = status(stand, auth)
    assert saved["groups"][0]["name"] == "Saved only"
    assert saved["routing"]["last_observation"] == applied["routing"]["last_observation"]
    assert saved["routing"]["desired_revision"] != saved["routing"]["last_observation"]["running_revision"]

    subprocess.run(["systemctl", "stop", stand["unit"].name], check=True, timeout=20)
    unavailable = request(stand, route, headers=auth)
    assert unavailable["status"] == 503 and unavailable["cache_control"] == "no-store"
    subprocess.run(["systemctl", "start", stand["unit"].name], check=True, timeout=20)
    control("status")
    assert status(stand, auth)["groups"][0]["name"] == "Saved only"
    print("Rebuilt panel authorization, sanitized status, observed routing and service recovery passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--http"]:
        call_panel()
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument("wgates")
        parser.add_argument("panel_root")
        args = parser.parse_args()
        main(args.wgates, args.panel_root, panel_acceptance=acceptance)
