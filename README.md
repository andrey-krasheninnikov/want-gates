# Want Gates

[Русский](README.ru.md)

Network routing and tunnel management for an existing 3x-ui gateway.

Want Gates is planned to route traffic from VLESS clients through outgoing
VPN connections selected by destination domains, IP addresses, and CIDR ranges.
Connections are organized into company groups with a primary and ordered
fallbacks.

## Status

The Rust binary provides local readiness, group and connection management,
and VLESS profile import through a Unix socket. Profiles are saved as desired
state without starting VPNs or changing 3x-ui. See
[service operation and the local API](docs/service.md).

Both `vless://` links and Xray outbound JSON are accepted. Validation is
structural; Xray compatibility and network behavior remain unverified.
VPN routing, native authentication, bootstrap, the skill package, and panel
integrations remain planned. No binary release or skill package is published.

## Planned routing model

1. A user connects to the VPS through VLESS in 3x-ui.
2. A destination rule selects a group.
3. The group selects a healthy connection that supports the required traffic.
4. If no eligible connection exists, traffic for that group is blocked.

Unmatched traffic goes directly from the VPS. Protected traffic never falls
back to a direct path or another company's connection.

Groups operate concurrently. Each connection has a group, name, protocol,
authentication state, DNS settings, and verified TCP/UDP and IPv4/IPv6
capabilities. Ambiguous rules of equal specificity are rejected.

## Planned connections and checks

- Outgoing VLESS through Xray.
- OpenVPN, Forti through openfortivpn, and WireGuard.
- NetBird private-network routes and exit nodes.
- Profile import and native authentication, including supported MFA/SSO flows.
- Connection-specific DNS for public and private destinations.
- Target-resource healthchecks, ordered failover, and automatic failback.

Default healthchecks run every 30 seconds with a 5-second timeout. Three
consecutive failures mark a connection unavailable; five consecutive successes
make a recovered primary eligible again. These settings are configurable per
group.

Simultaneous isolated NetBird accounts and UDP/IPv6 support for the Forti bridge
still require runtime validation. Session continuity during path changes or
Xray restarts is not guaranteed.

## Planned operation and installation

The Rust binary provides a CLI and local systemd service connected through
a Unix socket. Future routing changes require a preview and an explicit apply.

Bootstrap will install Want Gates beside an existing compatible 3x-ui, starting
with MHSanaei/3x-ui 3.8.5. It will preserve unrelated panel settings and check
the result of configuration changes.

The target is Linux with systemd on `x86_64` and `aarch64`. Dependency
installation is planned for `apt`, `dnf`, `pacman`, and `zypper`;
other systems receive preflight results and manual instructions. Compatibility
must be demonstrated for each supported environment.

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
