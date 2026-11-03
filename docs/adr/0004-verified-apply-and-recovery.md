# Verified apply and guarded recovery

Use a private loopback SOCKS inbound in the running Xray to verify each group's
TCP/UDP and IPv4/IPv6 path. The isolated acceptance stand additionally exercises
the real VLESS ingress. Resource access is a per-combination observation:
missing or failed probes leave that combination blocked. Optional group healthchecks provide continuous target checks and
ordered fallback selection.

The 3x-ui API replaces a full saved template and may apply it through hot reload
or restart. Record each candidate before sending it, compare saved readback,
and verify runtime rules and traffic. Apply may write a candidate followed by
a template that blocks unverified combinations. Preserve the panel's first API
rule and unrelated objects; take over only the shared local VLESS policy.

Read/compare/write cannot supply atomic upstream concurrency control. After
failure, restore only a base or known candidate confirmed by fresh inspection.
Intervening edits require manual reconciliation. Retain uncertain operations
across service restarts and require explicit recovery. A saved restoration
without prior traffic proof remains visibly unverified.
