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
mode selects only the advertised NetBird network ID in `exit_network_id`.
Enroll exit-mode peers into a dedicated NetBird distribution group and publish
only the configured exit to that group. Leave Auto Apply disabled. Give
unrelated routes distinct network IDs and let NetBird create the IPv6 companion
for the same exit. Keep exit-mode peers out of private route distribution and
Network resource policies, including broad policies that use `All` as a
source. When both modes share an account, use a separate policy source group
for private-mode peers. NetBird can install newly advertised private routes
before Want Gates reads the updated network list.
[NetBird exit node configuration](https://docs.netbird.io/use-cases/remote-access/exit-nodes)

Use IP/CIDR resources for protected private-mode destinations. Want Gates
deselects advertised domain resources. Use an explicit `--dns` resolver and
health targets reachable through the selected routes. For traffic that must
use the exit, choose destinations outside the NetBird overlay addresses.

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

Initial apply prepares the daemon with application traffic blocked. After
authenticating a static group, run `wgates routing preview` again and apply the
new plan ID. Groups with a configured healthcheck can admit traffic when the
target and required capability probes pass. Each connection gets its own
tunnel and resolver. Private mode suppresses the
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
reports the state and deadline without the URL or code. During device login,
the deadline is the local five-minute wait limit. The provider can expire the
code sooner. After login, the deadline reflects the session expiry NetBird
reports when one is available.

Setup keys and device codes are transient. NetBird keeps its enrolled peer
identity under the root-owned native state directory. On service restart, Want
Gates tries to reconnect unpaused connections with saved peer identities and
requires fresh traffic checks. A changed profile creates a new generation that
requires enrollment. After a disconnection, restart the connection. Repeat
login when NetBird requires authentication.

Log out to pause the connection and remove its network resources.

```sh
wgates connection logout CONNECTION_ID
```

Restart to clear the pause and reconnect with the saved peer identity.

```sh
wgates connection restart CONNECTION_ID
```

To remove the saved identity, log out before running `forget-auth`.

```sh
wgates connection logout CONNECTION_ID
wgates connection forget-auth CONNECTION_ID
```

Delete the retired peer in its NetBird control plane for remote revocation.

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
binary. Remove any `--netbird-bin` option from the native runtime's `ExecStart`
and `ExecStopPost` overrides before installing the older binary. Reload systemd
and restart Want Gates after installation.

```sh
sudo systemctl daemon-reload
sudo systemctl restart wgates.service
systemctl is-active wgates-native.service
```

Verify the intended protected paths and the gateway management route.

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
