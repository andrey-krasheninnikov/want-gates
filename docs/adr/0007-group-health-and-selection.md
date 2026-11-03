# Group health and one selected connection

A group can opt into automatic routing through an explicitly applied healthcheck.
Its primary and ordered reserves remain desired configuration; running selection
is separate. Required capabilities form an explicit nonempty admission set.

Choose one eligible connection for the whole group. Switch data and protected
DNS together. This keeps connection DNS consistent when reserves use different
company views. A connection missing one required combination cannot serve the
group, even when it could carry another combination. Other verified combinations
can still use the selected connection; unverified traffic stays blocked.

Probe the target and required capabilities through every prepared connection.
Keep periodic health separate from explicit verification. Apply thresholds to
availability and require stable recovery before restoring a higher-priority
path. Retain applied profiles for monitoring while desired edits wait for apply.

Reuse the control service's worker and guarded panel submission path. Avoid a
second daemon or public listener. This serializes checks with panel operations;
large or slow groups can delay later checks. Expose scheduling delays rather
than treating missed cycles as successful or failed probes. Preserve the
existing concurrency and session-interruption limits of the panel API.

TCP checks require an expected resource response prefix, with an optional test
request. A local proxy acknowledgement cannot substitute for resource access.
Silent ports need HTTP/HTTPS or a responding TCP health resource; they are not
marked healthy from a successful SOCKS handshake.
