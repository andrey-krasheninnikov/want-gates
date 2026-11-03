# Domain and IP routing through VLESS

Want Gates manages domain and IP/CIDR routing beside MHSanaei/3x-ui 3.8.5 with Xray
26.9.9. It controls the shared policy of enabled local VLESS inbounds. Rules
select a group; its explicit primary supplies the outgoing VLESS connection.
No fallback or continuous health monitoring runs in this slice.

## Configure and preview

Run the control service as described in [service operation](service.md).
Create a group and import a VLESS profile first. Send panel settings through a
file or stdin, never as a raw command argument:

```sh
wgates panel configure --file panel.json
wgates panel preflight
wgates group update GROUP_ID --primary CONNECTION_ID
wgates rule create --group GROUP_ID --destination 10.20.0.0/16
wgates rule create --group GROUP_ID --destination fd42:20::/64
wgates group update GROUP_ID --probe-file probes.json
wgates routing preview
wgates routing apply PLAN_ID
wgates routing status
```

The panel file contains `{"url":"http://127.0.0.1:2053/BASE/","token":"TOKEN"}`.
Use an administrative API token created in the panel. Want Gates does not
create or rotate it. HTTP is accepted only for literal loopback addresses;
HTTPS requires certificate verification. Redirects and environment proxies are
disabled. The service retains the settings privately and returns no token or
full URL. Protect input files separately.

All management commands accept `--socket PATH`. Use `--file -` or
`--probe-file -` for stdin. `wgates group update GROUP_ID --primary -` clears a
primary. A primary must belong to its group. Clear its reference before moving
or deleting the connection. Rules also prevent deleting their group.

`wgates rule list [--group GROUP_ID]`, `show`, `update`, and `delete` use the
same stable-ID and revision rules as connections. Updates accept `--group` and
`--destination`. An individual address becomes `/32` or `/128`; CIDRs are
canonicalized. Duplicate networks identify their conflicting groups and are
rejected. More-specific prefixes take
priority, including their blocking rules. IPv4-mapped IPv6 notation is rejected;
use IPv4 notation instead.

## Domain rules and connection DNS

```sh
wgates rule create --group GROUP_ID --destination corp.example
wgates rule create --group OTHER_GROUP_ID --destination dev.corp.example
wgates rule create --group OTHER_GROUP_ID --destination full:corp.example
wgates connection update CONNECTION_ID --dns udp://10.20.0.53:53
wgates routing preview
wgates routing apply PLAN_ID
```

A bare domain covers itself and subdomains. `full:` matches only that name.
Names are lowercased, converted to IDNA and stripped of one final dot. Longer
names take priority; an exact rule outranks a suffix rule at the same name.
Duplicate canonical rules are rejected with both groups' names and IDs.
Wildcard, regex and URL destination syntax are not supported.

A matching domain rule takes priority over IP/CIDR, including its blocking
behavior. Xray can use the domain supplied as a VLESS destination or recovered
through configured sniffing. Safe `routeOnly` sniffing keeps the original IP
while choosing the domain's group. Without a name, only IP/CIDR rules apply;
a previous DNS answer does not assign later numeric traffic to a domain.
Encrypted or unavailable names cannot be inferred. Supply IP/CIDR rules for
traffic that carries no usable domain.

Each connection accepts one `udp://IP:port` or `tcp://IP:port` resolver, including
bracketed IPv6. Set it during import with `--dns URI` or update it later.
`--dns -` clears it. Hostname endpoints, credentials, DoH/DoT and resolver lists
are not supported. DNS settings are ordinary connection metadata, separate from
the secret VLESS profile. A change takes effect only after preview and apply.

For groups with domain rules, configure a `dns` probe in the group probe file:

```json
{"dns":{"query_name":"health.corp.example","query_type":"A"}}
```

The query name must select that group. The probe uses its configured resolver
through the primary and checks an A or AAAA answer. Missing DNS, a missing probe,
a failed check or an unverified resolver transport blocks the domain path.
IP rules retain their separate transport observations. A DNS observation proves
that probe's lookup, not the existence of every name in a zone.

Managed VLESS ingress intercepts ordinary TCP/UDP DNS on destination port 53.
Protected A/AAAA queries use only the selected connection's resolver; CNAME
chains are handled while resolving those types. A failed lookup does not try
a parent group's, another company's or the panel's resolver. Unprotected A/AAAA
queries retain the panel DNS context, including its implicit system resolver
when no servers were configured. All other query types return REFUSED on this
intercepted path, including CNAME-type, SRV, TXT, MX and HTTPS queries.

Managed resolvers disable caching and stale answers. Switching primary selects
its own resolver and tag, even when two connections use the same resolver IP.
Named outgoing requests force local resolution in this DNS context and send
only an eligible IP family to VLESS. Sniffed numeric destinations retain their
original IP and are checked against the selected group's transport capability.
DNS outside the VLESS tunnel, arbitrary encrypted DNS, and client caches remain
outside this policy. Configure clients to send protected lookups through VLESS.

Domain preflight requires `routing.domainStrategy: AsIs` and the default or
`UseIP` global DNS query strategy. It rejects DNS scripts, system hosts,
protected-name hosts overrides and unbounded hosts patterns. A VLESS server
name must not overlap a protected domain, which could create a bootstrap cycle.
Reconcile incompatible settings in the panel; Want Gates does not silently
replace them. Existing DNS servers and other DNS fields retain their values.
The panel's automatic `xui-dns-allow` normalization is included in preview and
saved readback. Managed DNS tag routes terminate before those direct exceptions.

Preview includes group/connection resolver settings and panel DNS allow-rule
changes without exposing profiles or probe credentials. Apply and recovery
verify DNS alongside traffic and saved settings. Inspect the `dns` result inside
each group's capability observations in `routing status` after a partial result.

Preflight requires the pinned versions, accessible administrative endpoints and
a running Xray without a reported pending error. Preview rejects routing
scripts, reserved-tag collisions, references from unmanaged settings into the
managed objects, and outbound chains. Import still preserves extended outbound
JSON; apply currently requires each selected primary to be standalone.

When VLESS sniffing overrides a destination, enable `routeOnly` or disable
sniffing in 3x-ui first. Want Gates does not edit the panel's inbound records.
Keep the panel's internal `api` routing rule first. Reconcile and re-save legacy
panel settings before preview when this requirement fails.

Preview saves a private plan bound to the desired state, panel credentials,
full saved template, outbound test URL, and relevant inbound configuration.
It makes no panel update. A newer preview supersedes the preceding unused plan.
The public preview lists networks and ingress tags without profiles or secrets.

## Traffic verification and partial application

A probe file can contain these four optional entries:

```json
{
  "tcp_ipv4": {"url": "http://10.20.0.10:8080/health", "expected_status": 200},
  "udp_ipv4": {"server": "10.20.0.53:53", "query_name": "health.example", "query_type": "A"},
  "tcp_ipv6": {"url": "http://[fd42:20::10]:8080/health", "expected_status": 200},
  "udp_ipv6": {"server": "[fd42:20::53]:53", "query_name": "health.example", "query_type": "AAAA"}
}
```

Probe IP addresses do not require destination rules. Private per-group SOCKS
credentials bind these transport checks to the selected primary; ordinary
managed routing and DNS interception are verified separately.
Use unauthenticated resources: probe settings are ordinary group metadata.
HTTP probes require literal IPs, no credentials, query or fragment, and a final
status from 200 to 599; the default expected status is 200. They follow no
redirects and consume at most 64 KiB. DNS probes require an IP:port, an ASCII
name and an A/AAAA query. They check a successful response and an answer of the
requested type. A compressed DNS question is currently rejected. Neither probe
uses a local DNS lookup for its destination.

Explicit apply first installs a candidate permitting each primary's requested
traffic. It checks actual runtime rule selection, then sends HTTP and UDP/DNS
traffic through an authenticated SOCKS listener on `127.0.0.1`. The listener's
credentials are private and its routes match the managed VLESS policy. Only
successful combinations remain enabled in the final template. Missing probes,
missing primaries and failed probes result in blackhole routes. An unavailable
connection never selects direct or another group.

The result is `applied`, `partial`, or `blocked`. These are successful
configuration outcomes; inspect the per-group capability reasons. Transport
availability does not establish that every address in a CIDR is reachable.
Connection responses expose capabilities from the last matching apply. Desired
changes produce `pending_apply`; an incomplete operation produces `unknown`.
These observations are not a continuous health guarantee.

The managed direct outbound retains Xray's default behavior. Xray 26.9.9 has a
private-target guard for VLESS-originated freedom traffic. An outgoing VPN
server must permit the private destinations being tested. Want Gates does not
reconfigure that remote server or disable its safeguards. Protected-name DNS uses the selected connection; Want Gates does not change
the outgoing server's private-target safeguards.

## Apply, drift and recovery

Want Gates changes its prefixed inbounds, outbounds, DNS servers and routing
rules, plus the panel-owned DNS normalization described above.
The panel's API rule stays first. Managed VLESS policy then takes priority,
followed by a direct route for unmatched traffic from those inbounds. Other
inbounds and unrelated saved objects retain their settings and relative order.
Existing VLESS routing behavior changes under this shared policy, even though
the old objects remain saved.

Every update uses the administrative API and preserves `outboundTestUrl`.
Want Gates never edits the panel database or runtime files. It reads the panel
again before each write and rejects observed drift. This read/compare/write
sequence is not an atomic upstream transaction. Coordinate other panel writers
during apply and recovery. A change in the remaining race window cannot be
prevented by this API.

The service records each intended candidate durably before sending it. It
checks saved readback, runtime route selection and working traffic after apply.
An API acknowledgement or generated configuration alone is insufficient.
Repeated application of the same completed plan rechecks the observed result
without duplicating managed objects. Xray updates or restarts can interrupt
sessions.

After a technical failure, restoration is allowed only when fresh panel state
matches the recorded base or a known submitted candidate. Intervening edits
prevent restoration and leave `recovery_required`. A lost response is reconciled
through readback instead of repeating the update. After inspection, use:

```sh
wgates routing recover PLAN_ID
```

An incomplete apply blocks a new preview and changing panel credentials until
recovery. After a crash, `routing status` reports the retained journal and
`recovery_required: true`. Startup does not replay external writes. Preserve the
state directory when investigating failures.

Restoration keeps desired state unchanged. The previous configuration is called
verified only when its saved readback and retained runtime probes pass. The
first failed apply may restore the saved base without having prior traffic
proof; its result is `restored_runtime_unverified`. A restored older policy can
leave newly requested rules unapplied. Read desired and running revisions
before relying on them. A completed successful apply cannot be undone through
`recover`; create and review another desired configuration instead.

One network worker serializes panel operations. Readiness, object reads and
routing status remain available; configuration writes are rejected while it
runs. Panel requests and individual probes have five-second budgets. The
operation has a 300-second budget; CLI network responses allow 330 seconds.
Shutdown retains uncertain work for recovery instead of retrying it.

Private files under `routing/` hold panel credentials, the latest plan,
submission journal, working snapshot and last observation. The directory is
0700 and JSON files are 0600, owned by the service account. Files are bounded at
128 MiB; panel responses at 16 MiB; encoded panel updates and total active
profile input at 10 MiB. Keep these files and `secrets/` together in offline
backups. Retained temporary files are never treated as active state.

## Local acceptance

GitHub Actions has only a manual trigger. Task checks run locally:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
```

macOS cannot establish Linux systemd or network-namespace behavior. Use a
disposable local Ubuntu 24.04 systemd environment, such as a task-owned Docker
Desktop container with a private cgroup namespace, IPv6 and namespace creation
available. Mount sources read-only, keep build output in the disposable
container, expose no host ports and do not mount the Docker socket. Install
Python 3, curl, iproute2, ping, tcpdump, systemd and the pinned Rust toolchain.
Fetch official 3x-ui 3.8.5 artifacts and verify their pinned SHA256 before use.
Do not run these root fixtures on a shared or production host:

```sh
sudo python3 tests/systemd_smoke.py target/release/wgates
sudo python3 tests/routing_smoke.py target/release/wgates /path/to/verified/x-ui
```

The network fixture uses independent client, gateway, two VPN and resource
namespaces. It checks actual TCP/UDP over IPv4/IPv6, nested CIDRs, unmatched
direct, partial capability blocking, a stopped primary, source-address evidence,
real panel drift/failure/recovery, preservation, private files and restart.
It also checks domain-only groups, exact and suffix priority, sniffed names,
A/AAAA/CNAME, intercepted UDP/TCP DNS, missing and failed resolvers, primary DNS
context changes, DNS recovery and absence of direct or cross-group DNS leaks.
It uses RAW VLESS with test identities. Other transport/profile combinations
remain subject to individual connection verification. Each fixture removes its accounts, units, processes, files and namespaces.
Remove the task-owned container and its disposable data after testing; preserve
pre-existing resources. Linux/arm64 acceptance does not establish amd64 or a
corporate provider's live compatibility.
