# Run the control service

The first implementation provides control-service readiness and version
inspection. VPN connections, routing changes, and the bootstrap installer are
separate roadmap items.

## Build and commands

Use the pinned Rust toolchain:

```sh
cargo build --locked --release
./target/release/wgates --version
./target/release/wgates --help
```

Commands:

- `wgates serve [--socket PATH] [--state-dir PATH]` runs the service.
- `wgates status [--socket PATH]` queries the service and prints one JSON object.
- `wgates --version` prints the CLI version.

Errors go to stderr and return a nonzero status. The default socket is
`/run/wgates/control.sock`; the default persistent state directory is
`/var/lib/wgates`. Override paths must be absolute, and their parent directories
must already exist.

The service creates its socket directory with mode 0750 and its state directory
with mode 0700. Existing directories must belong to the service user, retain
owner access, and satisfy these restrictions: no access for others, no group
write on the socket directory, and no group access to the state directory.
The socket has mode 0660.

Existing files, symlinks, and sockets are not replaced. A normal SIGTERM or
SIGINT removes only the socket created by that process. After an abnormal
shutdown outside systemd, inspect the path and its owner before removing a stale
socket. The packaged systemd service manages its runtime directory.

## Manual systemd installation

These commands describe a new installation on a Linux host with systemd.
Inspect existing binary, account, and unit names before installing; do not
overwrite another deployment.

```sh
sudo install -m 0755 target/release/wgates /usr/local/bin/wgates
sudo install -m 0644 packaging/sysusers.d/wgates.conf /usr/lib/sysusers.d/wgates.conf
sudo systemd-sysusers /usr/lib/sysusers.d/wgates.conf
sudo install -m 0644 packaging/systemd/wgates.service /etc/systemd/system/wgates.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgates.service
sudo wgates status
```

The unit runs as the unprivileged `wgates` account. Root and authorized members
of its group can reach the control socket. Group membership grants access to
the control API. The service owns its persistent state; stopping the unit
removes runtime files and preserves state.

The current unit allows Unix sockets only and grants no network-management
capabilities. It starts with empty state and does not configure VPNs or 3x-ui.

## Local API version 1

Use one newline-terminated JSON request per connection:

```json
{"api_version":1,"command":"status"}
```

A successful response is:

```json
{"api_version":1,"ready":true,"version":"0.1.0"}
```

Error responses contain `api_version` and an `error` string. Requests and
responses are limited to 4096 bytes. Reads have a two-second total deadline.
The CLI rejects incompatible versions, malformed or incomplete messages, and
not-ready responses.

`ready` confirms that the local control service initialized its directories
and socket. It does not confirm VPN, DNS, or 3x-ui connectivity.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

The CLI tests start task-owned service processes in private temporary
directories and remove them afterward. They cover readiness, protocol errors,
fragmented messages, peer closure, permissions, existing-path preservation,
and bounded shutdown.

On a disposable Linux systemd host, build the release binary and run:

```sh
sudo python3 tests/systemd_smoke.py target/release/wgates
```

This fixture creates a uniquely named test account, unit, binary, runtime
directory, and state directory. It checks start/status, unauthorized access,
graceful stop, persistent state, and restart, then verifies cleanup. It is
intended for the isolated CI runner.
