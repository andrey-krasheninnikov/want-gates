# NetBird connections

Install [the native runtime](openvpn.md#prerequisites-and-manual-installation),
NetBird 0.83.2 and curl on a Linux gateway with systemd and TUN. Install the
root-controlled NetBird binary at `/usr/bin/netbird`, or set `--netbird-bin` in the
native runtime's systemd drop-in. Want Gates starts a private daemon for each
prepared connection. Enabling the standalone NetBird system service is not
required.

## Configure and apply

Create a NetBird profile:

```json
{
  "management_url": "https://netbird.example",
  "mode": "exit",
  "exit_network_id": "office-exit",
  "control_endpoints": [
    {"host": "relay.example", "port": 443, "transport": "tcp"},
    {"host": "idp.example", "port": 443, "transport": "tcp"}
  ]
}
```

Use `"mode": "private"` and omit `exit_network_id` for private networks. Exit
mode selects one advertised NetBird network ID and keeps its private routes.
Publish exit routes to these peers with Auto Apply disabled. Use IP/CIDR
resources for protected destinations. Resolve company names through the
connection's explicit `--dns` resolver, which must be reachable through its
tunnel.

The HTTPS management endpoint is included automatically. List any separate
signal, relay, and device authorization or token endpoints, with their exact
TCP or UDP ports. Use a trusted management server and TLS trust chain. The
native runtime resolves control names on the gateway during preparation and
pins those addresses. After control endpoints change, update the connection
profile and use a new preview and apply. NetBird uses relay transport and a userspace TUN interface.

```sh
wgates connection import --group GROUP_ID --name Office --protocol netbird --file netbird.json --dns udp://10.220.0.10:53
wgates group update GROUP_ID --primary CONNECTION_ID
wgates rule create --group GROUP_ID --destination corp.example
wgates group update GROUP_ID --probe-file probes.json
wgates routing preview
wgates routing apply PLAN_ID
```

Initial apply prepares the daemon with application traffic blocked. Apply
again after authenticating a static group. Groups with a configured healthcheck
can admit traffic when the target and required capability probes pass. Each
connection gets its own tunnel and resolver. Private mode suppresses the
tunnel default route for the bridge. The gateway routes unmatched traffic
directly and blocks protected traffic when the group has no eligible connection.

## Authenticate and recover

Pass a one-off NetBird setup key in a protected file with the shape
`{"setup_key":"ONE_OFF_KEY"}`, or stream that JSON with `--file -`.
`connection login` reports progress while the daemon connects.

```sh
wgates connection login CONNECTION_ID --file /path/to/private-login.json
wgates connection show CONNECTION_ID
```

Run `wgates connection login CONNECTION_ID` without a file to start native
Device Authorization. Repeat it to read the pending HTTPS URL, code and expiry.
Complete the sign-in in a browser you control. Use a provider configured for
device login. The explicit login response is sensitive. Ordinary status
reports the state and expiry without the URL or code.

Setup keys and device codes are transient. NetBird keeps its enrolled peer
identity under the root-owned native state directory. A service restart
reconnects the saved peer and requires fresh traffic checks. A changed profile
creates a new generation that requires enrollment. After a disconnected or
expired session, repeat the appropriate login or restart the connection.

```sh
wgates connection logout CONNECTION_ID
wgates connection restart CONNECTION_ID
wgates connection forget-auth CONNECTION_ID
```

Logout pauses the connection and removes its network resources. Restart uses
the saved peer identity and clears the pause. To forget a local identity, first
log out, then run `forget-auth`. Delete a retired peer in its NetBird control
plane if it also needs remote revocation.

## Validate and roll back

Reproduce the adapter smoke on a disposable Linux host. Use the pinned
artifacts and GeoIP preparation in the [NetBird isolation stand](netbird-isolation.md).

```sh
cargo build --locked --release
sudo python3 -B tests/netbird_adapter_smoke.py target/release/wgates \
    /path/to/x-ui /path/to/netbird /path/to/netbird-server /path/to/geodata
```

To disable routing through this adapter, log out its connections and apply a
reviewed plan that restores the intended eligible connections or blocks the
affected groups. Back up the two Want Gates state directories using the service
backup procedure before removing NetBird connections. Remove them from group
primary and fallback references, delete them, then preview and apply. Resolve
any retained native resources shown by `routing status` before downgrading the
binary. Verify the intended protected paths and the gateway management route.

For a source rollback, fetch current `main` and create a clean worktree on
`revert/12-netbird-routing` from `origin/main`. Use the adapter PR number and
merge SHA from GitHub. The first invocation lists the affected paths. The second
creates a local revert commit for review and publication in a separate PR.

```sh
sh tests/netbird_revert.sh "$adapter_pr" "$merge_sha"
sh tests/netbird_revert.sh --apply "$adapter_pr" "$merge_sha"
```

To remove the isolation fixture as well, revert the adapter first and then use
the [fixture rollback](netbird-isolation.md#rollback).
