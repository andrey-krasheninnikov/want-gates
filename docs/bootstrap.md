# Install Want Gates

Bootstrap installs wgates on a Linux systemd gateway that already runs
MHSanaei/3x-ui 3.11.0 with Xray 26.10.21. It expects the panel in x-ui.service
and its executables under /usr/local/x-ui. Install or update the panel separately.
The installer leaves the panel's service, database, routes and DNS in place.

## Download and verify

Download the bootstrap script, SHA256SUMS and one Linux archive from the same
[Want Gates release](https://github.com/andrey-krasheninnikov/want-gates/releases).
Choose the archive that matches uname -m. Verify the named script and archive
against the checksums from that release before running the installer. For example:

```sh
(
set -eu
version=v0.1.0
architecture=$(uname -m)
archive="wgates-$version-linux-$architecture.tar.gz"
grep -F "  $archive" SHA256SUMS | sha256sum --check --strict
grep -F '  bootstrap.sh' SHA256SUMS | sha256sum --check --strict
digest=$(sha256sum "$archive" | cut -d ' ' -f 1)
bash bootstrap.sh preflight --archive "$archive" --sha256 "$digest"
sudo bash bootstrap.sh install --archive "$archive" --sha256 "$digest"
sudo wgates status
)
```

Preflight inspects the OS, systemd, panel, archive and selected dependencies.
Install changes the gateway only after the package passes verification.
The initial install creates the wgates system account and enables
wgates.service. Root and members of the wgates group can use its socket.
Follow [panel configuration](routing.md#configure-and-preview) to add the
operator's panel API credentials and run wgates panel preflight.
Control-service readiness does not establish route, DNS or VPN health.

## Optional native protocols

Pass one --protocol option per native protocol you plan to use. The supported
values are openvpn, forti, wireguard and netbird. Native routing requires
IPv4 forwarding and a root-controlled Xray executable. Check the relevant
devices, kernel support and client versions
before installation. See [OpenVPN](openvpn.md), [Forti](forti.md),
[WireGuard](wireguard.md) and [NetBird](netbird.md).

| Distribution | Manager | Package names for native clients |
| --- | --- | --- |
| Debian and Ubuntu | apt | openvpn, openfortivpn, ppp, wireguard-tools |
| Fedora | dnf | openvpn, openfortivpn, ppp, wireguard-tools |
| Arch Linux | pacman | openvpn, openfortivpn, ppp, wireguard-tools |
| openSUSE Leap and Tumbleweed | zypper | openvpn, openfortivpn, ppp, wireguard-tools |

Bootstrap installs missing common tools and selected available packages.
Install NetBird 0.83.2 separately as a root-controlled client binary. OpenVPN
2.6.x and the supported Forti versions may be absent from a distribution's
repositories. For those cases, install a supported client manually and verify
its version before repeating preflight. Keep Arch package indexes aligned
with the installed system. The installer uses the existing indexes.

For a different install path or package manager, follow [manual systemd
installation](service.md#manual-systemd-installation). Confirm the panel and
Xray versions with wgates panel preflight. Published release and PR checks
report the versions and architectures actually exercised.

## Repeat an installation or recover

Repeat the same install command to verify an existing installation. Upgrades
can restart wgates and the native runtime, which can interrupt sessions. Back
up the service state before upgrading. The installer records hashes of its
files under /var/lib/wgates-install. If an existing file differs from both the
release and the installer receipt, inspect it and reconcile the installation
with the manual instructions.

On a failed startup, bootstrap restores its previous files and service state
when it recognizes them. It keeps package dependencies and persistent data.
After an interruption, use the same install command to reconcile a pending
change before installing again. If the installer reports an unrecognized
file, inspect the pending record and systemd status before making changes.
