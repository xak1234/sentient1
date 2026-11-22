# sentient1 changelog

## 1.2.1 — 2026-11-22

- Add Freeze once to detection popups, the dashboard and the elevated CLI.
- Keep disabled alert buttons readable in the dark theme and ensure native
  notification windows open visibly.
- Check the reader's recorded creation time, executable and live process handle
  before pausing it; reject exited, reused, critical, service and protected
  desktop processes, with an explanation beside the action.
- Track manual pauses for Resume once / Release all. Repeated manual clicks do
  not add suspension counts. A failed state save triggers an immediate resume.
- Pause only the recorded reader, including all components hosted in it. Manual
  freezing does not change response policy, trust rules or network access.
- Install the desktop incident dialog alongside the monitor. CLI-only installs
  retain a native fallback with a freeze choice when available.

## 1.2.0 — 2026-11-22

- Identify applications hosted by DLLHost using packaged and classic COM
  registration, loaded DLL paths and component signatures, without vendor rules.
- Identify the DLL named by Rundll32 and the services running in a Svchost PID.
  Shared or unresolved hosts remain explicitly ambiguous.
- Show hosted-component names in alerts, notifications, detection lists and
  readable evidence; include component provenance in JSON and HTML reports.
- Resolve older DLLHost alerts from their saved command lines and current
  registration, explicitly labelled as historical enrichment.
- Keep detection severity unchanged. Shared hosts cannot acquire permanent trust
  through the alert button, and one host's notification cannot silence another.
- Add the read-only `sentient1 inspect <pid> --json` diagnostic.

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
