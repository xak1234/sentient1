# sentient1 security model

The monitor runs as LocalSystem to subscribe to the Security event log and set
file audit rules. The desktop runs as the signed-in user. Administrative changes
use a short-lived UAC helper with an account-restricted named pipe, verification
of both endpoint process IDs, and an allowlist of supported operations. Program files and persistent configuration are
ACL-protected; optional notification secrets use DPAPI and administrator-only
permissions inherited from the upstream engine.

Report vulnerabilities privately through
[GitHub security advisories](https://github.com/xak1234/sentient1/security/advisories/new).
For ordinary bugs, use this repository's issue templates. Do not post notification
credentials, real decoy contents or private incident evidence in public issues.
The original project's issue tracker does not support these modifications.
There is no signed automatic release channel configured.

Automatic updates are disabled at configuration, installation, service and CLI
boundaries. This build contains no trusted upstream release repository, API URL
or signing key. A future release must define and review its own signed update
channel before enabling it. Local release checksums are not signatures.

Default reader attribution uses Windows Security event 4663. The optional
oplock accelerator uses timing inference and undocumented Windows layouts, can
misattribute a reader, and remains off by default. The stale-event guard rejects
known PID reuse; it does not eliminate every race between identity checks and
process operations. Protected/system processes are excluded from destructive
responses by the inherited engine rules.

Do not open bait files to preview them; use `bait show`. Avoid running ABA and
sentient1 against the same files. No live-malware testing has been performed.
This source review is focused, not an exhaustive security certification.

Reports may contain account names in local paths and network addresses. Command
lines are excluded by default, including parent command lines; they can be
explicitly included with `--include-command-lines`. Decoy text and notification
secrets are never included in the dashboard snapshot/report schema. HTML uses
Go's escaping template engine and has no JavaScript or external resources.
