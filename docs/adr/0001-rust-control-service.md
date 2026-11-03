# ADR 0001: Rust CLI and local control service

Status: accepted; local management and VLESS domain/IP routing and connection DNS are implemented.

## Context

Want Gates must expose the same operations through a CLI, a section in 3x-ui,
and local terminal integrations. The gateway already runs 3x-ui. A single
operator manages a shared routing policy for its connected VLESS clients.

## Decision

Build the control plane in Rust. Expose the user-facing command as `wgates`.
Use one binary with CLI and service modes. Keep persistent configuration writes
in the service and communicate over a Unix socket, without another public port.

Keep secrets separate from ordinary configuration with restrictive filesystem
permissions. Isolate authentication state for each connection. Do not expose
credentials in ordinary command arguments, plans, diagnostics, or logs.

The CLI, panel integration, and MCP tools use the same service operations.
Saving groups and profiles changes desired state only. Runtime configuration
changes require a preview and an explicit apply. Show desired
and running state separately after an unsuccessful operation.

Target Linux with systemd. Initial binary architectures are `x86_64` and
`aarch64`. Automatically install dependencies through explicitly supported
`apt`, `dnf`, `pacman`, and `zypper` paths. On other systems, report
missing dependencies and manual steps through preflight. This target does not
establish compatibility with every distribution before testing.

Bootstrap requires an existing compatible 3x-ui deployment. It preserves its
configuration and does not provision a fresh panel.

## Consequences

The service is the common boundary for management operations. Its local socket
and secret storage require access controls. Systemd installation, restart
behavior, and dependency detection need disposable Linux tests.

The current binary provides local management and VLESS domain/IP routing and connection DNS with
preview, explicit apply, traffic verification and guarded recovery. Profile
import validation remains structural. Native authentication,
automatic failover, bootstrap and panel UI remain planned. No binary release
has been published.
