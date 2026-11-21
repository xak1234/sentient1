# sentient1 changelog

## 1.1.0 — 2026-11-21

- Integrated Setup, navigation, response confirmations and live command output in
  one Windows application window; administrative work uses a verified UAC helper.
- Added a charcoal/green terminal theme, dark Windows 11 frame, status cards and
  paired stepped activity animation driven by monitor status and heartbeat.
- Embedded the shield icon for pinned shortcuts. Minimise keeps the running taskbar
  button and adds a notification-area icon with restore and exit actions.
- Replaced visible native scrollbars with wheel and keyboard navigation; tables
  retain their position across status refreshes.
- Added structured setup validation for account identity, stale configuration,
  unavailable decoys, dependencies and notification input. Existing custom decoys
  and credentials can be preserved.
- Added native UI checks, publication documentation, the maintainer-provided
  screenshot, release packaging and Windows CI.

## 1.0.0 — 2026-11-21

Initial independent Windows release, based on the supplied MIT-licensed ABA
source. Adds the Windows dashboard, conservative shared health verdict, local
HTML/JSON reports with default command-line redaction, safer recovery accounting,
alert-ID validation and larger random IDs, delayed-event PID reuse guard, actual
oplock lock counts, audit-first defaults and an independent product footprint.
Inherited upstream automatic-update authority is removed. Includes source,
release scripts, regression tests and third-party attribution.
