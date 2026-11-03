# Domain routing and connection DNS

Use the pinned Xray DNS module for protected A/AAAA lookups, including CNAME
chains, and route each resolver through its selected VLESS connection. A
matched server ends DNS selection and disables its own cache. Keep unrelated
panel DNS settings, and reject scripts, hosts or global strategies that would
prevent isolation. This avoids another DNS process while requiring a narrower
record set: intercepted queries for other types return REFUSED.

Domain rules use names supplied by VLESS or available sniffing. They precede IP
rules, without recording DNS answers as routing rules for later IP-only traffic.
Exact names outrank suffix rules at the same name; longer names outrank their
parents. Connection changes still require preview, explicit apply, traffic
verification and guarded recovery. Account for the pinned panel's automatic
private-DNS allow rules in the saved candidate before submitting it.
