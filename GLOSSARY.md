# Want Gates glossary

These terms describe the gateway, its routing policy and operator actions.

| Term | Meaning |
| --- | --- |
| Gateway | The Linux VPS that runs 3x-ui and Want Gates and routes traffic from connected VLESS clients. |
| Ingress | The client's incoming VLESS connection to 3x-ui on the gateway. |
| Connection | A named outgoing VPN connection with a group, protocol, protocol settings, authentication state, DNS settings, and supported capabilities. |
| Group | A collection of connections for a company or routing purpose. Routing rules select a group. Multiple groups can operate concurrently. |
| Primary | The preferred connection within a group. |
| Fallback | A reserve connection in the same group. Reserves have an explicit order and must satisfy the traffic's required capabilities. |
| Routing rule | A domain, subdomain, IP address, or CIDR destination assigned to a group. Ambiguous rules of equal specificity are rejected. |
| Domain rule | A routing rule for a named domain and its subdomains. |
| Exact domain rule | A routing rule for one domain name without its subdomains. |
| Unmatched traffic | Traffic that does not match a Want Gates routing rule. Its default path is direct from the gateway. |
| Protected traffic | Traffic assigned to a group. It must not leave directly or through another group when the intended path is unavailable. |
| Capability | A connection's verified support for TCP, UDP, IPv4, or IPv6. Missing support must not cause direct fallback. |
| Capability limit | An operator-configured upper bound on a connection's TCP/UDP and IP-family combinations. Each permitted combination still requires traffic verification. |
| Connection verification | An explicit resource and DNS check through one prepared connection, without selecting it as primary or changing active routing. |
| Capability observation | A recorded result for one connection transport and IP family. It describes the last explicit verification rather than continuous health. |
| Connection DNS | DNS used through an individual connection for destinations assigned to its group, including private company zones. |
| Required capabilities | The explicit set of traffic combinations that one connection must support to serve an automatically managed group. |
| Health state | A connection's target-resource availability after the group's failure and recovery thresholds. It is separate from explicit capability verification. |
| Healthcheck | A probe of a group-configured target resource through each connection, including DNS when the target uses a hostname. |
| Failover | Selecting an eligible fallback when a preferred connection is unavailable. |
| Failback | Returning new connections to a recovered connection with higher priority after the required successful healthchecks. Existing sessions may be interrupted by path changes or Xray restarts. |
| Native generation | One prepared version of a system VPN connection. Its identity separates current access evidence from earlier processes and profiles. |
| Effective DNS | The resolver currently selected for a connection: its explicit DNS setting or a supported resolver supplied by its VPN server. |
| Network namespace | An isolated Linux network environment for an individual system VPN client, with separate interfaces, routes, and DNS handling. |
| Structural validation | Checking profile syntax and required field structure without executing Xray or proving compatibility, authentication, or connectivity. |
| Object revision | A saved object version used to reject stale updates and deletion requests. Renaming and moving retain the object ID. |
| Desired state | The configuration requested by the operator and saved for application. It may differ from the running state after a failed apply. |
| Running state | The configuration and connections actually active on the gateway. |
| Apply plan | A validated preview of proposed changes to Want Gates and its managed 3x-ui settings. |
| Apply | The explicit operation that applies a reviewed plan, checks the result, and restores the previous working state on failure where safe. |
| Managed settings | The 3x-ui objects owned by Want Gates. Unrelated panel settings remain under the operator's control. |
| Bootstrap | Installation of Want Gates and required dependencies beside an existing compatible 3x-ui deployment. It does not install 3x-ui on a clean VPS. |
| wgates | The user-facing CLI command and the command used by service, SSH, skill, and terminal integrations. |
| Control-service readiness | Confirmation that the local service initialized its state directory and control socket. It does not establish VPN, DNS, or panel health. |
| Want Gates skill | A portable instruction package distributed through the existing skills CLI and used locally to call wgates on a chosen VPS over SSH. |
| Warp Terminal integration | Workflows, a Tab Config, and MCP tools for operating Want Gates from Warp Terminal. |
