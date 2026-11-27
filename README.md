# Want Gates

[Русский](README.ru.md)

Network routing and tunnel management for an existing 3x-ui gateway.

Want Gates routes traffic from VLESS clients through outgoing VLESS or isolated OpenVPN/Forti connections
selected by destination domains, IP addresses, and CIDR ranges. Connections
are organized into company groups with an explicit primary and ordered fallbacks.
Optional target-resource checks switch data and DNS together within a group.

## Status

The Rust binary manages groups, VLESS/OpenVPN/Forti profiles, domain/IP rules and connection
DNS through a Unix
socket. A preview and explicit apply configure 3x-ui 3.11.0 with Xray 26.10.21.
The existing 3x-ui 3.8.5 and Xray 26.9.9 pair also works with the CLI.
TCP/UDP over IPv4/IPv6 are verified separately; unavailable combinations are
blocked. Operators can limit each connection and verify a prepared connection
without changing primary. See [service operation](docs/service.md) and
[routing, verification and recovery](docs/routing.md).

Both `vless://` and complete outbound JSON imports are supported. Import checks
structure; apply checks the panel and actual traffic. The isolated local
Linux/arm64 stand exercises two groups and the complete VLESS ingress path.
OpenVPN and Forti use an optional privileged helper for isolated native authentication and
routing. See [OpenVPN operation](docs/openvpn.md) and [Forti operation](docs/forti.md). The skill package and panel UI remain planned.

## Routing model

1. A user connects to the VPS through VLESS in 3x-ui.
2. A destination rule selects a group.
3. The group selects a healthy connection that supports the required traffic.
4. If no eligible connection exists, traffic for that group is blocked.

Unmatched traffic goes directly from the VPS. Protected traffic never falls
back to a direct path or another company's connection.

Groups operate concurrently. Each connection has a group, name, protocol,
authentication state, DNS settings, and verified TCP/UDP and IPv4/IPv6
capabilities. Ambiguous rules of equal specificity are rejected.

## Connections and checks

- Outgoing VLESS through Xray.
- Isolated OpenVPN with certificate, password and supported native MFA/SSO authentication.
- Isolated Forti through openfortivpn with password, certificates, OTP/push, cookie SSO and native SAML.
- [WireGuard](docs/wireguard.md) through the Linux native runtime.
- [NetBird](docs/netbird.md) private networks and exit nodes through the Linux native runtime.
- Profile import and native authentication, including supported MFA/SSO flows.
- TCP, HTTP and HTTPS target checks, ordered failover, and stable failback within a group.

Default healthchecks run every 30 seconds with a 5-second timeout. Three
consecutive failures mark a connection unavailable; five consecutive successes
make a recovered connection eligible again. These settings are configurable per
group.

Forti supports separately verified TCP/UDP over IPv4; IPv6 stays blocked. Session continuity during path changes or
Xray restarts is not guaranteed.

## Installation

[Install wgates](docs/bootstrap.md) beside an existing 3x-ui 3.11.0 gateway.
The Linux packages target systemd on x86_64 and aarch64.

## Planned integrations

A version-specific patch and panel build will add status and management to
3x-ui. Warp Terminal integration will provide Workflows, a Tab Config, and MCP
tools. Local integrations will call `wgates` on a selected VPS over SSH.

The future skill package will use the existing skills CLI:

```sh
npx skills@latest add andrey-krasheninnikov/want-gates
```

This command is the planned distribution interface. The skill package has not
been published yet, and it will not replace installation of the server binary.

## Project documentation

- [Glossary](GLOSSARY.md)
- [Control service and local API](docs/service.md)
- [Architecture decisions](docs/adr/)
- [Project conventions](AGENTS.md)
- [Issue tracker](docs/agents/issue-tracker.md)
- [Product specification](https://github.com/andrey-krasheninnikov/want-gates/issues/1)
- [Roadmap and tickets](https://github.com/andrey-krasheninnikov/want-gates/issues)

## License

[MIT](LICENSE).
