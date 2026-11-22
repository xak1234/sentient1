# sentient1 1.2.1

This update identifies applications running inside Windows host processes and
adds a manual **Freeze once** action to alerts and the Detections page.

## Changes

- Show hosted application and component evidence for DLLHost, Rundll32 and
  Svchost. Registered, loaded, multiple and unresolved identities are labelled;
  historical enrichment is distinguished from evidence captured at detection.
- Display the reader name, process ID and affected file prominently in alerts.
- Add **Freeze once** and **Resume once** controls. Disabled buttons remain
  readable and the alert explains why freezing is unavailable.
- Validate process creation time and executable before freezing. Exited readers,
  reused IDs, critical Windows processes, system services and protected desktop
  processes are excluded.
- Track manual pauses for recovery, avoid duplicate manual suspension and resume
  immediately if saving the recovery record fails.
- Keep shared-host approvals temporary, preventing permanent trust of every
  application that happens to use the same Windows host.

Manual freezing pauses the recorded process, including all components hosted
inside it. It does not pause child processes or change automatic response policy,
trust rules or network access. Older alerts without a recorded creation time
cannot safely offer Freeze once.

## Download and update

Download **sentient1_1.2.1_Windows_x64_Source.zip** and extract it. Keep
**sentient1.exe** beside **sentient1-Desktop.exe**. Windows 10/11 x64 and the
**.NET 8 Desktop Runtime x64** are required.

Close the older dashboard, open the new **sentient1-Desktop.exe**, then use
**Setup → Review & apply** to update the installed monitor. Review and preserve
your existing settings before applying. Windows requests administrator permission
for changes. The new incident window is installed alongside the monitor.

The ZIP includes both executables, full source, build scripts, documentation and
licence notices. **SHA256SUMS.txt** accompanies the ZIP; executable checksums are
also included inside. This release is not code-signed.

## Verification

Go formatting, vet and tests passed. The .NET desktop built with nullable analysis
and warnings treated as errors; formatting and analyzer checks passed. A real
disposable process was frozen and resumed, duplicate Freeze requests were tested,
and a forced recovery-record save failure restored the process automatically.
Native UI checks covered the alert window, disabled-button readability, dashboard
controls and administrator helper. Installed diagnostics reported 17 healthy
decoys with the monitor running and its configuration preserved.

Based on the MIT-licensed A Better Antivirus engine; attribution is retained.
See **SECURITY.md** for the detection model and limitations.
