# OpenVPN connections

OpenVPN runs in a separate Linux network namespace for each prepared connection.
The control service stays unprivileged. A root helper owns native processes,
interfaces and firewall rules. A private authenticated Xray bridge carries data
and probes; its application path stays closed until resource checks pass.

## Prerequisites and manual installation

Install the control service using [service operation](service.md). Native routing
requires Linux with systemd, OpenVPN 2.6.x, Xray 26.9.9, iproute2, nftables,
`getent`, `sysctl` and `/dev/net/tun`. Executables and their parent directories
must be controlled by root and unwritable by other users. The default Xray path
is `/usr/local/x-ui/bin/xray-linux-arm64` or `xray-linux-amd64`.

Check the gateway's forwarding policy before enabling native routing. IPv4
forwarding must already be enabled. IPv6 VPN endpoints additionally require
IPv6 forwarding. Preflight reports missing prerequisites. Want Gates never
changes global forwarding settings, the host's default route or its DNS.

Install the optional helper beside the same binary:

```sh
sudo install -m 0644 packaging/systemd/wgates-native.service /etc/systemd/system/wgates-native.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgates-native.service
```

Inspect existing installation paths and unit names before replacing them. The
helper is ordered before `wgates.service` and follows its stop/restart lifecycle.
VLESS-only installations do not require the helper. For another Xray location,
use a systemd drop-in that replaces both `ExecStart` and `ExecStopPost` with the
packaged commands plus `--xray-bin /absolute/path/to/xray`.

The default helper socket is `/run/wgates-native/control.sock`. Its group can
reach the socket, but requests require root or the exact control-service UID.
`wgates serve --native-socket PATH` selects an alternate helper socket. Helper
state is root-owned mode 0700 in `/var/lib/wgates-native`; files are mode 0600.
Keep this directory and `/var/lib/wgates` together in offline backups. Alternate
state and socket directories also require root-controlled parent directories.
The helper refuses an occupied socket path; inspect its owner after an abnormal
stop before removing a stale socket.

## Import and apply

```sh
wgates connection import --group GROUP_ID --name 'Office OpenVPN' --protocol openvpn --file client.ovpn
wgates group update GROUP_ID --primary CONNECTION_ID
wgates rule create --group GROUP_ID --destination corp.example
wgates group update GROUP_ID --probe-file probes.json
wgates routing preview
wgates routing apply PLAN_ID
wgates connection show CONNECTION_ID
```

Configure resource probes as described in [routing](routing.md). Import checks
structure and packages the profile; it does not establish authentication or
traffic support. Only successful checks advertise TCP/UDP and IPv4/IPv6.
Unsupported or unavailable combinations stay blocked.

Supported profiles use `client`, `dev tun`, TLS and one or more `remote` entries.
They can contain inline CA, certificate, private key, extra certificates,
TLS-auth/crypt keys, CRL and PKCS#12 assets. Certificate and private key must be
supplied together, and an explicit CA is required. UDP and TCP client transport
options are accepted. Native OpenVPN still validates cryptography and option
combinations when starting the connection.

For `--file client.ovpn`, referenced assets must be regular files with one hard
link below that profile's directory. Nested directories are allowed. Absolute
paths, parent segments, symlinks and special files are rejected. Stdin requires
inline assets. The packaged profile is limited to 1 MiB. Executable hooks,
plugins, nested configurations, arbitrary management/log paths, proxy options,
external credential files and unsupported directives fail explicitly. Use the
login commands for credentials. Endpoint bootstrap uses the host resolver and
pins supported numeric unicast addresses. Loopback, unspecified, multicast,
IPv4-mapped IPv6 and link-local IPv6 endpoints are rejected.

An explicit connection `--dns` overrides server-provided DNS. Otherwise the
first supported numeric server DNS becomes the effective resolver. Lookup
failure never selects another resolver. `--dns -` restores server DNS selection.
The effective resolver and authentication state appear in connection status. When the panel blocks
`geoip:private`, its 3x-ui 3.8.5 DNS exception requires the selected private
resolvers to use one port. Use a common port across groups and their reserves,
or reconcile that panel policy before preview; a conflicting automatic switch
stops with a visible error.

## Authentication

Apply prepares the native connection before login. It can finish as `blocked`
or `partial` while authentication is pending. Read the current action explicitly:

```sh
wgates connection login CONNECTION_ID
wgates connection login CONNECTION_ID --file auth.json
wgates connection login CONNECTION_ID --file auth.json --remember
```

`--file -` accepts JSON over stdin. Every reply must name the current
`challenge_id`; stale and already answered challenges are rejected. Protect
input files yourself. There are no password or OTP command arguments.

For a username/password action:

```json
{"challenge_id":"CURRENT_ID","username":"USER","password":"PASSWORD"}
```

For an encrypted key:

```json
{"challenge_id":"CURRENT_ID","private_key_password":"KEY_PASSWORD"}
```

Static challenges additionally require `response` alongside base credentials.
Dynamic CRV1 and CR_TEXT actions accept the current ID and `response`:

```json
{"challenge_id":"CURRENT_ID","response":"ONE_TIME_RESPONSE"}
```

A web action returns an HTTPS URL only from explicit `connection login`. Open it
on the operator's computer and complete authentication there. The gateway opens
no browser or public callback listener. Standard WEB_AUTH and OPEN_URL are
supported; proxy variants and vendor-specific extensions fail explicitly.
Ordinary status omits challenge prompts, IDs, URLs and credentials.

`expires_at` gives the pending deadline. Expired challenges require a fresh login
or restart. Authentication and resource access are separate: successful login
alone does not admit traffic. An automatically managed group uses its configured
healthchecks; a group without healthchecks needs another preview and apply.
A native restart, new session or effective DNS change invalidates earlier access
evidence. Session continuity is not guaranteed.

Only `--remember` persists base credentials. OTP, challenge state, browser URLs
and native authentication tokens stay transient. Saved credentials are private
plaintext protected by root ownership and filesystem permissions.

```sh
wgates connection logout CONNECTION_ID
wgates connection restart CONNECTION_ID
wgates connection forget-auth CONNECTION_ID
```

Logout stops that connection and removes its network resources while retaining
explicitly remembered credentials. Login resumes a stopped connection. Restart
starts a fresh native session with its application path closed. Forget-auth
removes saved base credentials for that connection and clears remembered values
from its prepared sessions; it does not revoke an already established VPN session.

## Recovery and cleanup

Inspect `routing status` after an interrupted operation before retrying. Native
preparation is journaled before side effects. Use the reported plan ID with
`routing recover` to reconcile an incomplete apply. Recovery checks panel state
and native generation identity before restoration or cleanup. If the previous
native session or DNS changed, restoring its old access evidence requires fresh
verification through another preview and apply.

Old native generations are retired only after the new panel state is confirmed.
`native_retained` lists resources whose cleanup still needs reconciliation.
Changed firewall rules, links or namespace ownership stop automatic deletion.
Inspect retained resources and restore known ownership before applying again.
Never remove native state to hide a cleanup failure.

Normal helper stop removes owned runtime networking and keeps preparation and
remembered credentials for restart. `native-cleanup` is the root maintenance
mode used by `ExecStopPost`; run it manually only after stopping the helper.
Its arguments must match the unit's socket, state, service user and Xray paths.
Unknown resources are retained for inspection.

## Local acceptance

On a disposable Linux systemd host with the real 3x-ui 3.8.5 installation:

```sh
sudo python3 tests/openvpn_smoke.py target/release/wgates /path/to/x-ui
sudo python3 tests/native_safety_smoke.py target/release/wgates /path/to/xray
```

The fixture creates its own certificates, VPN servers, namespaces, account and
units. It uses public CLI commands and VLESS ingress traffic, then cleans its
owned resources. It requires root and must not run on a live gateway. Native
acceptance uses synthetic credentials and controllable servers. Corporate VPN
providers and interactive identity-provider policies need separate live checks.

Runtime acceptance covers Linux aarch64, OpenVPN 2.6.19 and Xray 26.9.9.
The stand exercises UDP over IPv4 and TCP over IPv6 as VPN transports, with
verified TCP/UDP and IPv4/IPv6 payloads. An amd64 runtime and UDP over IPv6
transport remain unverified.
