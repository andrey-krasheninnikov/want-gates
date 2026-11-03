# Run the control service

The service manages groups, VLESS profiles, domain/IP rules and connection DNS.
Saving an object
changes desired state only. Routing requires a preview and explicit apply
through 3x-ui. See [routing and recovery](routing.md). Native authentication remains planned.

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

The unit allows Unix, IPv4 and IPv6 sockets for the local control API, panel
requests and traffic probes. It grants no network-management capabilities and
does not alter host routes or interfaces. Shutdown has a 15-second systemd
budget.

## Groups and connection profiles

```sh
wgates group create --name 'Example company'
wgates group list
wgates group show GROUP_ID
wgates group update GROUP_ID --name 'New company name'
wgates connection import --group GROUP_ID --name 'Office VPN' --protocol vless --file profile.txt
wgates connection list --sort group
wgates connection list --group GROUP_ID
wgates connection show CONNECTION_ID
wgates connection update CONNECTION_ID --name 'Backup VPN' --group OTHER_GROUP_ID
wgates connection update CONNECTION_ID --file replacement.json
wgates connection update CONNECTION_ID --dns udp://10.20.0.53:53
wgates connection update CONNECTION_ID --dns -
wgates connection delete CONNECTION_ID
wgates group delete GROUP_ID
```

Add `--socket PATH` to any management command. `--file -` reads stdin. Profiles
must be UTF-8 and at most 1 MiB. Pass credentials through a file or stdin; the
CLI has no raw-profile argument, secret export, or reveal option. Manage input
files separately: importing does not change their permissions or delete them.

Names contain 1 to 128 characters, without surrounding whitespace or control
characters. Group names are unique; connection names are unique within a group.
Names and sorting are case-sensitive. IDs remain stable across renaming, moves,
and profile replacement. The protocol cannot be changed by an update.

A group referenced by connections or rules cannot be deleted. A primary cannot
be deleted or moved until its group reference is cleared or changed. Automatic
fallback is not implemented.

Connection lists sort by group name, connection name, and ID by default.
`--sort name` sorts by connection name and ID. The CLI collects service pages
before printing one JSON result; an intervening configuration change fails the
listing explicitly instead of mixing versions.

### VLESS import and limits

Accept one `vless://` link or one standard JSON outbound with `protocol: vless`.
JSON supports the shortened settings shape and `vnext` with exactly one endpoint
and one user. Required fields include address, port 1–65535, nonempty ID, and
explicit nonempty encryption. The shortened and `vnext` shapes cannot coexist.
Duplicate JSON keys and duplicate URI parameters are rejected.

Outbound JSON is retained in full, including extended Xray 26.9.9 transport,
VLESS Encryption, REALITY, and finalmask settings. Validation checks syntax,
required fields, and basic types. It does not reproduce Xray's semantic,
cryptographic, file-reference, or transport-combination validation. A structurally
accepted profile may still be rejected by Xray. No Xray binary is required.

URI import maps the published VLESS sharing parameters to an outbound:
TCP/RAW, mKCP, WebSocket, gRPC, XHTTP, and HTTPUpgrade; TLS and REALITY;
flow and encryption; transport path/host, mKCP seed/header/MTU/TTI,
gRPC service/authority/mode, XHTTP extra, finalmask, and published TLS/REALITY
parameters. Removed transports, unsupported URI extensions, and parameters
that do not apply to the selected transport/security fail explicitly. Use
outbound JSON for settings the sharing format cannot represent. URI descriptions
are not used as connection names. Supply `--name` explicitly.

Routine responses contain metadata and `validation: structural`. Before apply,
runtime is unavailable and capabilities are empty. After apply, responses expose
the last matching capability observation; changed desired state is pending and
incomplete operations are unknown. Native `authentication` remains
`not_attempted`; VLESS traffic verification is reported separately.
Other protocol adapters report unavailable. No authentication sessions are
created in this slice; future native adapters must isolate state per connection
outside ordinary configuration.

### Persistent state

The service holds an exclusive advisory lock on its state directory, including
when another process chooses a different socket. `config.json` uses schema
version 2, a configuration revision, stable object IDs, and per-object revisions.
Schema 1 loads with empty rules, primary and probes; the next saved mutation
writes schema 2. Existing schema 1/2 data defaults to no connection DNS and no
DNS probe. Existing routing snapshots and recovery journals remain readable.
Older binaries reject the extended configuration. Downgrading
requires an offline migration rather than a reset.
It contains metadata and profile references. Its limit is 16 MiB.

Profiles are plaintext in separate `secrets/` files. The directory is 0700;
configuration and profile files are 0600 and owned by the service user. State
files must be regular files with one hard link. Symlinks and unsafe permissions
are rejected. Socket access permits management operations, but responses never
include the stored profile. Existing empty state is accepted without migration.

A replacement profile is written to a new private file and synced before an
atomic configuration rename. Unreferenced profiles are removed only after
configuration-directory durability is confirmed. A post-rename sync failure
retains both profile versions. Startup validates saved references and profiles
and confirms directory durability before removing orphaned
files from its reserved profile namespace. Unknown filenames are retained.
Corrupt configuration or missing profiles cause startup to fail; data is never
silently reset. Make offline backups of the complete state directory together.

After an error that says configuration was saved but durability or cleanup is
uncertain, inspect the object before retrying. Stop the service before manual
state repair. Following an interrupted write, retained `.config-*.tmp` files
may require inspection and offline removal; they are never treated as saved
configuration.

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
responses are limited to 4 MiB, excluding the terminating newline. Request reads
and ordinary responses have a two-second total deadline. The CLI allows 330
seconds for routing operations and panel preflight.
The CLI rejects incompatible versions, malformed or incomplete messages, and
not-ready responses.

`ready` confirms that the local control service initialized its directories
and socket. It does not confirm VPN, DNS, or 3x-ui connectivity.

### Management requests

Management uses the same one-request-per-connection framing. Commands are
`group.create`, `group.list`, `group.show`, `group.update`, `group.delete`,
`connection.import`, `connection.list`, `connection.show`, `connection.update`,
`connection.delete`, `rule.create`, `rule.list`, `rule.show`, `rule.update`,
`rule.delete`, `panel.configure`, `panel.preflight`, `routing.preview`,
`routing.apply`, `routing.status`, and `routing.recover`.

Create groups with `name`. Import connections with `name`, `group_id`,
`protocol`, and the source text in `profile`; `dns` optionally supplies a numeric
UDP/TCP resolver URI. Show uses `id`. Update and delete
require `id` and `expected_revision`, obtained from a prior show. Updates supply
only changed fields: group `name`, `primary` (ID or null), or `probes`; connection
`name`, `group_id`, `profile`, or `dns` (URI or null); rule `group_id` or
`destination`. Unexpected
fields are rejected. Stale revisions fail without a write;
the CLI supplies these revision preconditions automatically.

Rule creation requires `group_id` and `destination`. Rule listing accepts the
same pagination fields as other lists and an optional `group_id`.
`panel.configure` takes a `settings` object containing `url` and `token`.
`panel.preflight`, `routing.preview`, and `routing.status` have no extra fields.
`routing.apply` and `routing.recover` require `plan_id`.

Management responses wrap their result in `data`. Routing status includes
`desired_revision`, `busy`, `recovery_required`, and `last_observation`. A caller
disconnect does not cancel an accepted operation. Inspect status before retrying.
See [routing operation](routing.md) for observation and recovery semantics.

Successful management responses contain `api_version` and `data`. Lists return
up to 100 objects, `list_revision`, and nullable `next_offset`. Continue with
`offset: next_offset` and the same `list_revision`. Connection lists optionally
accept `group_id` and `sort: group|name`. Changing configuration invalidates an
in-progress listing. Configuration writes are serialized. One worker performs
network operations while reads remain available. Inspect state after a transport
failure before retrying a mutation.

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
graceful stop, saved group/profile persistence across restart, and cleanup. It is
intended for a disposable local Linux systemd host. See
[local network acceptance](routing.md#local-acceptance) for the real VLESS stand.
