# ADR 0003: Integrate with 3x-ui through its API and a minimal panel patch

Status: accepted design; deployment is planned.

## Context

The baseline is MHSanaei/3x-ui 3.8.5. Its Xray API reads and replaces the saved
template. Updating the template can apply changes live or restart Xray.
A failed application can leave saved and running state different.

The checked frontend is compiled into the panel binary. Adding a section
requires a frontend change and a rebuilt panel.

## Decision

Use the administrative 3x-ui API for Xray configuration. Preserve unrelated
settings, re-read before applying a plan, reject observed configuration drift,
and read back both saved settings and runtime results. Do not edit the panel
database or the runtime Xray configuration file directly.

Keep a previous working snapshot. On failure, restore it only when doing so
will not overwrite intervening changes; otherwise report the mismatch and
required recovery. Verify recovery before reporting success.

Do not describe a read/compare/update sequence as an atomic upstream
transaction. The baseline API replaces a full template and has no per-object
patch operation in its Xray controller. Concurrent edits need explicit tests
and coordination before stronger guarantees are claimed.

Maintain a minimal version-specific patch that adds a Want Gates section to
3x-ui. The panel uses its existing authorization and a local backend connection
to the Rust service. Add status first, then management and preview/apply.
Distribute a tested panel build while retaining upstream notices.

Do not promise uninterrupted sessions: unsupported live updates or errors can
cause a full Xray restart. A synthetic route-selection test is not evidence
that traffic traverses the intended connection.

## Consequences

Pin and test the panel baseline before replacement or upgrade. Preserve its
configuration and verify the resulting process state. A panel build for another
version is not supported merely because its API looks similar.

References:

- [3x-ui 3.8.5](https://github.com/MHSanaei/3x-ui/releases/tag/v3.8.5)
- [Xray controller](https://github.com/MHSanaei/3x-ui/blob/v3.8.5/internal/web/controller/xray_setting.go)
- [Runtime application](https://github.com/MHSanaei/3x-ui/blob/v3.8.5/internal/web/service/xray.go)
- [Adding a panel page](https://github.com/MHSanaei/3x-ui/blob/v3.8.5/CONTRIBUTING.md)
