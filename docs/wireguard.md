# WireGuard connections

The native runtime creates a Linux WireGuard interface in each connection's
network namespace. Install the shared [native runtime](openvpn.md#prerequisites-and-manual-installation),
iproute2, nftables and the `wireguard-tools` package. The kernel must support
WireGuard interfaces. IPv4 forwarding is required by the native bridge.
An IPv6 peer endpoint also requires host IPv6 forwarding; IPv6 payloads over an
IPv4 endpoint do not. The runtime leaves host routing, forwarding settings and
DNS under the operator's control.

```sh
wgates connection import --group GROUP_ID --name 'Office' --protocol wireguard --file office.conf
wgates group update GROUP_ID --primary CONNECTION_ID
wgates rule create --group GROUP_ID --destination corp.example
wgates group update GROUP_ID --probe-file probes.json
wgates routing preview
wgates routing apply PLAN_ID
wgates connection show CONNECTION_ID
```

One `[Interface]` and one `[Peer]` are supported. Supply `PrivateKey`,
`Address`, `PublicKey`, `Endpoint` and `AllowedIPs`. Use up to 32 interface
addresses and 256 allowed prefixes. IPv4 and IPv6 addresses and prefixes can
share a profile. `Endpoint` takes an IP or hostname with a port. Bracket an
IPv6 literal. The helper resolves a hostname with the host resolver during
preparation and pins one IP for that generation. Reimport the profile with
`connection update --file` and apply it to resolve the endpoint again.

`PresharedKey`, `PersistentKeepalive`, `MTU` and one numeric `DNS` address
are optional. The import rejects other fields, including hooks, custom tables
and firewall marks. The helper passes keys to `wg setconf` through private
input and uses its own firewall mark to route encrypted packets to the peer.
The default profile resolver uses UDP port 53 through the tunnel. An explicit
connection `--dns` overrides it, and `--dns -` restores the profile value.

`configured` means the helper installed the keys and interface. The shared
probes establish TCP, UDP and IP-family capabilities. A failed probe does not
identify a key mismatch by itself. Configure a target-resource healthcheck to
select eligible reserves and admit a fresh runtime session automatically.
Groups without a healthcheck require another explicit preview and apply after
restart. Use `connection restart` or `connection logout` for the runtime
session. To rotate keys, update the profile and apply the new plan.

The isolated Linux stand exercises WireGuard with 3x-ui and VLESS.

```sh
sudo python3 tests/wireguard_smoke.py target/release/wgates /path/to/x-ui
```

Run the fixture on a disposable systemd host with a compatible 3x-ui build and
the shared native prerequisites. It creates its own keys and peer interfaces.
