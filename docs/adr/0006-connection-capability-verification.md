# Connection capability verification

A connection exposes four independent combinations: TCP/UDP over IPv4/IPv6.
Operator limits bound the candidates; only successful traffic checks establish
support. Missing checks, failed access, stale evidence and configured limits
remain distinct. DNS availability also depends on the configured resolver's
transport, not the record type it answers.

Prepare private per-connection diagnostic routes through the existing Xray SOCKS
listener during preview/apply. Explicit connection verification can then probe
an unselected connection without switching primary, adding a process, or writing
the panel. Diagnostic access obeys configured limits. Ordinary protected traffic
uses only the combinations verified by its explicit apply.

Bind observations to connection settings and group probes. Keep latest
verification separate from applied policy and continuous health. Verification
cannot enable routes; apply repeats selected-primary checks. Native adapters and
future fallback selection use the same capability vocabulary and admission
rules. Network failure does not establish an authentication cause.

All prepared profiles enter the panel candidate and share its size and runtime
compatibility constraints. Retain drift checks and guarded recovery. Existing
state remains readable; old plans require a fresh preview before application.
