# Issue tracker: GitHub

Specs and tickets live in GitHub Issues for
andrey-krasheninnikov/want-gates.

Use `gh` with an explicit repository argument. Read the complete issue
body, labels, and comments before working from an existing issue.
Use `--body-file` for multiline issue and pull request bodies.

Publish one issue per spec or ticket. Each ticket references its parent
spec and lists its blockers. Use native GitHub blocking relationships
when available; otherwise retain explicit blocking links in the body.
Do not close or rewrite the parent spec when publishing tickets.

Inspect current state before a write and read it back afterward.
Reconcile an ambiguous result before retrying.

## Pull requests as a triage surface

**PRs as a request surface: no.**
