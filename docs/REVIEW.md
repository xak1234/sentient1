# Source review and implementation notes

Date: 21 November 2026. Input: `B:\.git2\utils\aba`.
The original directory has no `.git` metadata, so the exact upstream revision
is unknown. Its licence is MIT, copyright 2026 Flytrap contributors.

## What the supplied app actually does

ABA plants fake passwords, recovery material and unused app profiles. It adds
NTFS file SACL entries, enables successful File System auditing and subscribes
to Security event 4663. `AccessMask & FILE_READ_DATA` identifies a recorded read;
the event supplies the reader PID, executable and file. Classification combines
path, Authenticode publisher, scripting-host rules, cross-application decoy
sweeps and process evidence. Responses include suspension, per-executable WFP
blocking and optional host isolation. It has no trained AI detector and does not
scan all executable content for known trojan signatures.

The secondary oplock path requests an exclusive opportunistic lock. Windows
signals a competing open; the engine snapshots blocked threads and compares
which ones wake when the lock is released. This is timing inference, not a
Windows-supplied PID for the opener. It uses undocumented NT structures and a
shared-kernel-data offset. sentient1 keeps the mechanism opt-in and describes
that limitation explicitly. An audited read is evidence of access, not proof
that the reader is malicious; backup, indexing and sync software can trigger it.

## Findings addressed

1. **False healthy status:** the terminal headline previously considered service
   state and bait status without incorporating failed health checks or stale
   heartbeat into its decision. Both sentient1 interfaces now use one stricter
   assessment and require audited decoys plus a recent heartbeat.
2. **Failed recovery forgotten:** release cleared isolation/adapter records even
   after network-operation errors. Resume/kill could resolve an alert despite
   failed operations. Successful results now clear only matching recorded state;
   errors propagate and unresolved operations remain retryable. Alert-write
   failures are also reported. Unknown recorded process creation time blocks
   resume/kill rather than authorizing a bare PID action.
3. **Unsafe alert path:** alert identifiers were directly joined into filesystem
   paths. Both reading and saving now reject non-identifier syntax, and loaded
   JSON IDs are validated. New random IDs use 8 bytes rather than 2.
4. **Delayed-event PID reuse:** a replayed Security record could refer to a PID
   now owned by a newer process. The added FILETIME/event-time guard records a
   historical warning and avoids acting on the known-reused PID. This is a
   targeted guard, not a claim that every process-identity race is eliminated.
5. **Oplock count was requested watchers:** the count previously included paths
   whose lock was not granted. It now counts granted locks. Real-OS tests wait
   for lock readiness rather than assuming a fixed 100 ms delay is sufficient.
6. **Unsafe fork update identity:** the original repository/key would have made
   a renamed fork trust upstream binaries. sentient1 has separate service, data,
   mutex, WFP IDs and no enabled release channel or inherited key.
7. **Misleading speed claims:** current user-facing test and help text no longer
   promises that an oplock-based response happens before any byte can be read.
8. **Evidence portability:** new escaped, offline HTML and JSON exports omit
   reader/parent command lines by default, while keeping the local evidence.

## New application structure

The .NET 8 Windows Forms dashboard invokes the Go executable using separate
argument-list entries, without constructing a shell command. It provides a
read-only status view without elevation. Version 1.1 embeds setup and a green
terminal in the same native window. Administrative operations run in a
short-lived UAC helper; an account-restricted named pipe verifies both endpoint
process IDs and accepts only specific operations. No command shell is opened.
Five-second refreshes do not overlap.
Read-only calls have a bounded timeout; errors retain a stale-data notice rather
than displaying a healthy state. Reports use Go `html/template`, including
escaping of untrusted process names and paths, with no scripts or remote assets.

## Version 1.0 validation evidence

- Windows x64 Go build and native desktop build completed.
- `go vet ./...` and the Go unit/OS-level suite passed after the changes.
- Desktop compiled with nullable checking and warnings treated as errors;
  formatting/analyzer verification is included in the build script.
- Real Windows audit integration test detected a harmless `cmd.exe` read in
  **704.649 ms** during the measured run. This is one observed run, not a speed
  guarantee or a malware-blocking benchmark.
- Real WFP integration test blocked and unblocked a private temporary copy of
  curl; its filter cleanup completed. Whole-host isolation was not exercised.
- Native desktop smoke check created the form and parsed the real CLI snapshot;
  the actual dashboard window was visually checked for readable layout.
- CLI version, JSON status, disabled update check and HTML report generation
  were exercised. Initial status correctly says **Not installed**.

No live malware corpus was run. A full install/uninstall/whole-host-isolation
cycle on a disposable VM remains a separate validation step. The original source folder was preserved. The user installed the protection
service after the initial release; version 1.1 development preserves that
configuration and the existing decoys. The selective audit integration test restores the prior
File System auditing setting.

## Version 1.1 verification

- Go vet and the complete ordinary Go test suite passed on Windows x64.
- .NET release build: zero warnings/errors with nullable analysis and warnings
  treated as errors; formatting/analyzer verification passed.
- Startup smoke: all native pages, embedded shield, taskbar setting, real JSON
  status and administrative-operation allowlist passed.
- UI smoke: visited all five pages, validated the current real configuration,
  streamed a read-only doctor command through the elevated named-pipe helper,
  minimised with the taskbar button and tray icon retained, then restored.
- Setup validation did not apply changes. The existing 17-decoy installation
  remained active. Reconfiguration/uninstall/containment were not exercised on
  this user's live monitor as part of the UI test.
- Native views were visually inspected for layout and readable contrast.
- The pinned shortcut was repaired to reference the executable's embedded icon.
- Header activity uses two animated staircases with a gap and pauses on stopped
  or stale status; the Windows 11 title bar uses the dark application colours.
- Native scrollbars were removed. Real UI checks verified setup-page wheel,
  Page Down and Home navigation, plus wheel and End/Home keys in the decoy grid.
  Grid position is retained during automatic snapshot refresh.
- Installed engine binaries were updated to 1.1.0 with the configuration hash
  unchanged; the service returned to running with 17 healthy audited decoys.

## Primary references

- Microsoft, Security event 4663:
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663
- Microsoft, opportunistic locks:
  https://learn.microsoft.com/en-us/windows/win32/fileio/opportunistic-locks
- Microsoft, FSCTL_REQUEST_OPLOCK:
  https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock

These document the audit/oplock primitives. They do not validate ABA's
thread-timing attribution heuristic or certify sentient1's detection coverage.
