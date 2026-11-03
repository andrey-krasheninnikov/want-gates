# Forti connections

Forti uses openfortivpn in the [shared native runtime](openvpn.md). Each prepared
connection has its own network namespace, PPP interface, routes and Xray bridge.
Private mount views hide host PPP options and hooks, root home and runtime files.
The native client cannot change host DNS or the management route. Its route and
resolver writes are disabled; Want Gates installs the private PPP route.

## Prerequisites

Install the control service and optional helper using [OpenVPN operation](openvpn.md).
Forti requires Linux with systemd, IPv4 forwarding already enabled, `/dev/ppp`,
pppd 2.4.9, openfortivpn 1.21.x through 1.24.x, Xray 26.9.9, iproute2, nftables
and the common native helper tools. Executables and their parents must be
controlled by root. OpenVPN itself is required only for OpenVPN connections.

The default client is `/usr/bin/openfortivpn`; pppd is `/usr/sbin/pppd`.
Native SAML requires openfortivpn 1.23 or newer; explicit `sni` requires 1.22
or newer. To use a separately installed client, replace both `ExecStart` and
`ExecStopPost` in a helper drop-in with the packaged commands plus
`--openfortivpn-bin /absolute/path/to/openfortivpn`. Install and validate that
client separately. Bootstrap installation remains planned.

## Profiles and routing

```sh
wgates connection import --group GROUP_ID --name 'Office Forti' --protocol forti --file client.conf
wgates group update GROUP_ID --primary CONNECTION_ID --probe-file probes.json
wgates rule create --group GROUP_ID --destination corp.example
wgates routing preview
wgates routing apply PLAN_ID
wgates connection login CONNECTION_ID
```

Minimal profile:

```ini
host = vpn.example.net
port = 443
ca-file = company-ca.pem
```

The system trust store is used when `ca-file` is absent. Native certificate and
hostname validation remain enabled. `trusted-cert` accepts an explicit SHA-256
certificate fingerprint using openfortivpn's native trust semantics: it can
accept that exact certificate when ordinary validation fails. Confirm the
fingerprint through a trusted channel before importing it.

Supported options are `host`, `port`, `realm`, `trusted-cert`, `sni`, `min-tls`
(1.2 or 1.3), `otp-prompt`, `otp-delay` (0 through 60), and `no-ftm-push`.
Native route/DNS flags are accepted for import but forced off; `persistent`
must be zero. `ca-file`, `user-cert` and `user-key` package relative PEM assets
with the same path and 1 MiB limits as OpenVPN. A client certificate and key
must appear together. Stdin accepts canonical JSON with `protocol: "forti"`,
`options` pairs and inline PEM assets.

Credentials in profiles, hooks, plugins, external credential files, PKCS#11,
pinentry, arbitrary PPP configuration and unsafe TLS options are rejected.
Endpoint bootstrap uses the host resolver and pins IPv4 addresses privately;
protecting that endpoint's own domain with the same group is rejected.

An explicit `--dns` overrides the first supported IPv4 server DNS. The selected
resolver is reached through the connection; failure never selects a public
resolver or a hosts-file answer. Target probes and group healthchecks use the
same bridge as VLESS traffic. Successful authentication alone grants no access.
TCP and UDP over IPv4 require separate successful probes. IPv6 is unsupported
and blocked, even if the connection's configured capability limit includes it.
See [routing](routing.md) for fallback, admission and recovery.

## Authentication

Use `connection login CONNECTION_ID` to obtain the current `challenge_id` and
supported methods. Submit private JSON with `--file PATH` or `--file -`.
No password or OTP appears in command arguments. Ordinary status omits prompts,
challenge IDs, tokens and browser URLs.

```json
{"challenge_id":"CURRENT_ID","username":"USER","password":"PASSWORD"}
```

A client certificate may accompany account login. For certificate-only login,
use `method: "certificate"`. Add `private_key_password` for an encrypted PEM key,
including when using SSO. Native passphrase input is limited to 31 bytes and
cannot preserve leading or trailing whitespace. Native username/password limits
are 64/256 bytes. Protect profile exports and input files yourself.

OTP tokeninfo and supported HTTP 401 form prompts return a new text challenge:

```json
{"challenge_id":"CURRENT_ID","response":"ONE_TIME_RESPONSE"}
```

Push approval remains pending while the operator approves it externally.
Cookie SSO accepts the native cookie value over private stdin:

```json
{"challenge_id":"CURRENT_ID","method":"cookie","cookie":"SVPNCOOKIE=SESSION_VALUE"}
```

Native SAML starts with `method: "saml"`. Its web action returns an HTTPS `url`
and `ssh_forward` containing the VPS relay's loopback port. Before opening the
URL on the operator's computer, start:

```sh
ssh -N -L 127.0.0.1:8020:127.0.0.1:REMOTE_PORT VPS_ALIAS
```

Use the returned `remote_port` for `REMOTE_PORT`. Local port 8020 must be free.
Complete the browser flow within 50 seconds. The VPS opens only a temporary
loopback listener. Completion, expiry and logout close it. Stop the SSH forward
afterward. An expired flow requires a fresh login; stale replies are rejected.
Cookie SSO remains available on clients without native SAML. Vendor-specific
flows outside these native methods are unsupported.

`--remember` saves only account/key base credentials in root-owned plaintext
files, as for OpenVPN. SSO input and OTP cannot be remembered. Restart closes
admission and requires fresh resource verification; a remembered password/key
can authenticate again. Logout removes that connection's resources.
`connection forget-auth` deletes saved credentials without revoking an already
established session. Unknown cleanup resources remain available for inspection.

## Local acceptance

On a disposable Linux systemd host with openfortivpn 1.24.1 installed at
`/opt/forti-1.24.1/bin/openfortivpn` and legacy 1.21.0 at `/usr/bin/openfortivpn`:

```sh
sudo python3 tests/forti_smoke.py target/release/wgates /path/to/x-ui
sudo python3 tests/forti_smoke.py target/release/wgates /path/to/x-ui --legacy-client
```

The stand runs real openfortivpn and pppd 2.4.9 against a controlled TLS/PPP
peer. It tests authentication, company DNS, overlapping networks, VLESS TCP/UDP,
resource failures and same-group fallback. Native SAML uses a real SSH forward.
The fixture owns and removes its namespaces, services and synthetic credentials.
Run it only on a disposable host. These checks establish controlled Linux
aarch64 behavior, not corporate identity-provider compatibility.
