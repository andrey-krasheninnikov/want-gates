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
