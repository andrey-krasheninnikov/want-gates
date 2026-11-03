# Native clients use a separate privileged runtime

The control service stays unprivileged. A separate systemd process of the same
binary owns network namespaces, native clients and private Xray proxy bridges.
Its Unix socket accepts only the control-service identity and root, and its
operations never accept shell commands or arbitrary filesystem paths.

Each connection generation has separate interfaces, state, management socket
and credentials. Namespace filtering permits only the native client's transport
to its VPN endpoints outside the TUN. Diagnostic access and admitted application
traffic remain separate. Restarting a process or authenticating a new session
cannot reuse an earlier generation's admission without fresh resource checks.

Native authentication is asynchronous. Apply can complete with the connection
blocked while credentials or browser authentication are pending. Group
healthchecks can admit it after successful checks; groups without healthchecks
need another explicit preview and apply. Only an explicit remember operation
persists base credentials. OTP, challenge state and browser URLs stay transient.

An explicit DNS setting overrides supported server-provided DNS. DNS changes
invalidate the associated access evidence. Host forwarding is a checked
prerequisite; the runtime does not change global sysctl or the management route.
This runtime extends the single-worker design in ADR 0007 with the privileged
operations required by native clients. Health selection stays in the control
service. OpenVPN is the first adapter; other native adapters remain unavailable.

The private bridge uses VLESS over fixed TCP ports, carrying UDP without exposing
ephemeral relay ports. Separate identities keep diagnostics apart from admitted
traffic. The namespace permits numeric destinations through the TUN and native
control traffic only to pinned VPN endpoints. The control service retains group
selection, capability checks and recovery; the helper owns native resources.

Linux acceptance uses controlled OpenVPN servers and public CLI/VLESS traffic.
It does not establish compatibility with corporate identity providers or every
OpenVPN profile feature.
