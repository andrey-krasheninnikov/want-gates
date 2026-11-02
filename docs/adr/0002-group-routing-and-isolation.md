# ADR 0002: Group routing, connection isolation, and failover

Status: accepted design; runtime compatibility is unverified.

## Context

A user connects to the gateway through a VLESS ingress in 3x-ui. Companies can
require different outgoing VPNs, private DNS zones, and reserve connections.
Several groups must operate at the same time on one gateway.

## Decision

Each connection has a group, name, and protocol. Support outgoing VLESS,
OpenVPN, Forti through openfortivpn, WireGuard, and NetBird. Import existing
profiles and use the clients' native authentication methods, including MFA
or SSO where the selected client supports them.

Routing rules assign domains, subdomains, IP addresses, or CIDR ranges to a
group. A group defines a primary and ordered fallbacks. Reject ambiguous
rules of equal specificity. Unmatched traffic goes directly from the gateway.

Protected traffic may use only eligible connections in its group. Check
availability and the capabilities needed by that traffic. If none qualifies,
block it. Never substitute a direct path or a connection from another group.

The core supports TCP, UDP, IPv4, and IPv6. A connection advertises only verified
capabilities; unsupported traffic is blocked with a clear reason. Configure
DNS per connection and resolve the group's destinations through the selected
connection, without an external DNS fallback for protected names.

Use Xray for outgoing VLESS. Run native OpenVPN, openfortivpn, WireGuard, and
NetBird clients in separate network namespaces. Their state, interfaces,
routes, and DNS must remain isolated. Preserve the host's management route.

Healthchecks access a configurable target resource through each connection.
A process or interface being up is insufficient. Defaults per group are:

- interval: 30 seconds;
- timeout: 5 seconds;
- unavailable after 3 consecutive failures;
- primary eligible for failback after 5 consecutive successes.

Return new connections to the primary after stabilization. Do not promise
uninterrupted existing sessions when a path changes or Xray restarts.

## Consequences and acceptance gates

Prove routing and DNS behavior from a VLESS client to a target resource.
Include TCP/UDP, IPv4/IPv6, failures, recovery, capability mismatches, and
absence of direct or cross-group leaks.

NetBird must support private networks and exit nodes while carrying only
traffic selected by Want Gates. Its documented profiles support one active
profile. Multiple isolated native instances require a separate acceptance
gate before concurrent-account support is claimed.

The inspected Forti pattern establishes a namespace and proxy bridge, but
its confirmed traffic support is TCP only. UDP and IPv6 require new proof.

References: [NetBird profiles](https://docs.netbird.io/client/profiles),
[NetBird CLI](https://docs.netbird.io/get-started/cli).
