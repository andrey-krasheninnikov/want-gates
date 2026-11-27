# Want Gates in 3x-ui

The Want Gates section is built into 3x-ui 3.11.0 with Xray 26.10.21. It uses
the existing panel login and a local Unix socket to read gateway status. The
panel serves it under its configured base path.

The status page shows company groups, connections, destination rules,
authentication, capability observations, and health. It labels desired routing
and the last observed selection separately. A saved change appears in the
desired revision as soon as the service accepts it. The running revision remains
the last one observed by the service.

The panel connects to `/run/wgates/control.sock` as its own service account.
The packaged `wgates` service restricts the socket to its owner and group.
If a local installation uses `wgates serve --socket PATH`, set
`WGATES_CONTROL_SOCKET` to the same absolute path in the panel service environment.

## Build the panel

Run on Linux x86_64 or aarch64 with Go 1.27.3, Node.js 26.0.0, and
`musl-gcc`.

```sh
packaging/panel/build.sh panel-dist
```

The recipe checks the pinned 3x-ui source revision, applies the patch and
overlay, and uses the upstream dependency locks. It verifies the upstream
archive before replacing the panel executable. The archive retains the original
Xray, assets and service files. A corresponding source archive contains the
patched panel source and upstream license.

To use the build with an existing 3x-ui 3.11.0 installation, stop the panel
service and back up its database and panel executable. Replace its executable
with `x-ui/x-ui` from the matching archive, preserving the service owner and
executable permission. Start the service and open Want Gates after signing in.
To roll back, stop the service, restore the previous executable and restart.

## Manage routing

In Want Gates, add a company group, import a connection and assign destination
rules. The connection list is ordered by company group. Open an existing object
to inspect or edit it. Removing or moving an object requires changing its active
references first. Enter an IP address, a CIDR, or a domain such as
`example.org` to include its subdomains. Use `full:example.org` for an exact
domain match.

For a new connection, select VLESS, OpenVPN, Forti, WireGuard or NetBird. Paste
a self-contained profile or choose a local file. For OpenVPN and Forti, include
the needed inline assets or import a packaged JSON profile. Existing private
profiles remain in the service. An empty profile field keeps the saved profile
when editing. Connection DNS and allowed transport capabilities are editable
separately.

Edit a company group to choose its primary and reserve order. Configure a
resource URL, required capabilities and the health thresholds for automatic
selection. Transport and DNS probes use the same JSON format as the CLI.
When an edit conflicts with a newer revision, refresh and reopen the object.

Save changes to the desired configuration. Open **Preview routing** to inspect
the destinations, eligibility and ingress before choosing **Apply reviewed
routing**. An applied result can be partial or blocked. The status card shows
the last observed revision and any mismatch. Use **Recover routing** when
the service reports interrupted application. Refresh status after an
unconfirmed response before submitting another operation.

## Native VPN sign-in

Apply the current profile before opening its sign-in controls. Use
**Check sign-in** to read the current challenge or **Start or resume sign-in**
to initiate the connection. The panel shows the input requested by the adapter.

- OpenVPN accepts the configured account, key passphrase and supported
  password or text challenges. Browser authentication uses the link supplied
  by the adapter.
- Forti supports the methods reported by the installed client. For SAML,
  start the displayed SSH forward on the computer opening the sign-in link
  and use your usual server SSH alias.
- NetBird accepts a one-time setup key or browser sign-in with the displayed
  device code.
- WireGuard uses the keys in its profile. The native control can restart or
  disconnect an applied connection.

The panel sends credential and challenge input through the authenticated
session to the local service. Use HTTPS when connecting to the panel remotely.
Remembering supported base credentials requires an explicit selection. VPN
authentication is followed by resource verification before traffic is admitted.
