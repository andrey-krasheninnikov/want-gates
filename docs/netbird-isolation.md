# NetBird isolation stand

Issue [#11](https://github.com/andrey-krasheninnikov/want-gates/issues/11) exercises
two native NetBird accounts on one gateway. The connection adapter is tracked in
[#12](https://github.com/andrey-krasheninnikov/want-gates/issues/12).

## Reproduce

Use a disposable Linux systemd host with TUN, network namespaces, IPv4 and IPv6
forwarding in the test namespaces, and nftables. The fixture also uses Python 3.10 or later,
curl, OpenSSL, tcpdump, iproute2, nsenter and Rust 1.93. Run it as root. Reserve the host for
the test, since the routing stand creates systemd units and local accounts.

Use NetBird client and combined server v0.83.2, 3x-ui v3.8.5 and its Xray v26.9.9.
For Linux arm64 verify these artifacts before extracting them. Place the Xray
executable in root-controlled directories that the bridge user can traverse. Some
archives can preserve a non-root file owner when extracted as root.

| Artifact | SHA-256 |
| --- | --- |
| `netbird_0.83.2_linux_arm64.tar.gz` | `856eece869b6e2808760cc0e3f30d8f9d639728e5c1c5410a8895de28d7244e0` |
| `x-ui-linux-arm64.tar.gz` | `2dd601a32426fb19b0eafdffaead374a9cdb66be4dfb39407f9f50fa4e7234e7` |
| `netbirdio/netbird-server` image index | `47e43b1b9e6343eb99d99a612513579111439dd016805912b0fae95ce802b908` |

Get the combined server executable at `/go/bin/netbird-server` from the pinned
image. If using Docker, create the extraction container with name
`wgates-11-netbird-artifact` and label `want-gates.issue=11` so it can be removed
with the cleanup script. Save the full container ID printed by Docker.

```sh
# Once on the disposable host with internet access. NetBird verifies its downloads.
python3 -B tests/netbird_smoke.py --prepare-geodata /path/to/netbird-server /path/to/geodata

cargo build --locked --release
native_test=$(cargo test --locked --bin wgates --no-run --message-format=json |
    python3 -c 'import json, sys; print(*(m["executable"] for m in map(json.loads, sys.stdin) if m.get("executable")), sep="\n")')
test -x "$native_test"
sudo python3 -B tests/netbird_smoke.py \
    target/release/wgates /path/to/x-ui "$native_test" \
    /path/to/netbird /path/to/netbird-server --geodata /path/to/geodata
```

## Runtime decisions for #12

- The fixture uses the common veth, namespace, nftables and VLESS bridge code.
  It registers two ordinary VLESS connections to those bridges through the
  public CLI. This keeps fixture support out of the release binary.
- Each native daemon has its own `NB_STATE_DIR`, profile path, Unix socket, TUN
  interface and WireGuard port. Interface names live in separate namespaces.
  Each control plane uses a separate local owner, database and relay secret.
  Setup keys pass through temporary files and the local bootstrap PAT stays
  inside the fixture.
- Each gateway daemon uses its own relay. The common firewall allows the pinned
  control-plane and relay endpoint and blocks direct payload egress from the
  namespace. NetBird leaves system DNS management disabled. Want Gates resolves
  the two protected zones through their connection-specific resolvers, which
  share the same private IP. [Client settings](https://docs.netbird.io/get-started/cli).
- The exit is offered with auto-apply disabled. The test selects it on each
  daemon and uses resource witnesses outside the private routes to confirm its
  effect. The gateway retains its IPv4 and IPv6 default routes and 3x-ui access.
  [Exit node selection](https://docs.netbird.io/use-cases/remote-access/exit-nodes).

## Acceptance result

Linux arm64, NetBird v0.83.2, 3x-ui v3.8.5 and Xray v26.9.9. Both companies
returned the correct resource identity over TCP and UDP on IPv4 and IPv6,
first over private routes, then over selected exit nodes. The private LANs
and resolvers used overlapping addresses. The fixture verified distinct
daemon state, sockets and WireGuard ports, and checked resource and resolver
logs for cross-company or direct traffic.

A stopped serving traffic and DNS when its daemon stopped and deregistered.
B kept serving traffic through A's restart and setup-key registration.
A recovered its private and exit paths. Gateway defaults, policy rules and
the 3x-ui management API remained available.

The observed GeoIP cache was dated `20261013`. These results cover the local
embedded IdP setup-key flow and forced relay mode. Direct peer connectivity,
corporate SSO and Linux amd64 runtime still need separate verification.

## Rollback

Remove the run-specific GeoIP cache with the other extracted artifacts. A normal run stops the fixture processes and removes their namespaces, bridge
rules, test credentials, temporary state and routing stand resources. If it is
interrupted, stop the disposable environment. A Docker run may be removed by
exact IDs. Save those IDs at creation and label the lab container
`want-gates.issue=11` with name `wgates-11-linux`. The script checks the context,
names, labels and mounts before acting.

```sh
sh tests/netbird_cleanup.sh desktop-linux "$lab_id" "$artifact_id"
sh tests/netbird_cleanup.sh --apply desktop-linux "$lab_id" "$artifact_id"
```

If you extracted artifacts into a private host directory, remove that run's
downloads and extracted binaries after verifying the path. This fixture does
not configure a live NetBird account or install a NetBird service on the host.

To reverse the merged code, fetch `origin/main` and create a clean rollback
worktree. Get the full merge commit from [PR #31](https://github.com/andrey-krasheninnikov/want-gates/pull/31). Keep a copy of the script from the current `main` so it remains available
after the revert. The first invocation displays the exact paths in the merge.
The second creates a local revert commit. Publish it in a separate PR to
`main` after reviewing the diff.

```sh
git fetch origin main
git worktree add -b revert/11-netbird-isolation ../want-gates-revert-11 origin/main
cd ../want-gates-revert-11
sh tests/netbird_revert.sh 31 "$merge_sha"
sh tests/netbird_revert.sh --apply 31 "$merge_sha"
git show --stat HEAD
```

If later changes conflict with the revert, inspect them before resolving the
conflict. Use `git revert --abort` in that rollback worktree to abandon the
in-progress revert. Any separate NetBird adapter requires its own rollout and
rollback procedure.
