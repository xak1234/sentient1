# Changelog

## v0.5.4

- **A sweeping program is frozen before it gets the third app's data.** Instant freeze identifies who opened a
  bait by letting the open finish and seeing who wakes, so a program going through several apps' data was
  frozen just *after* opening the third, and a quick one (`find.exe` in a test) could read it and exit first.
  Now, when a program that already read two other apps' data is among those paused inside the open, it's
  frozen while still paused: it never gets the file.

## v0.5.3

- **Fix: instant freeze could blame the wrong program.** When ABA itself read one of its baits (its health
  check does, a second after the service starts), instant freeze looked for whichever program woke at that
  moment but left ABA's own threads out, so a program that happened to wake then could be reported as the
  opener and frozen for a read it never made. ABA's own reads are now recognised and blamed on no one.
  Found through an intermittent end-to-end test failure.

## v0.5.2

- **Stealers that run on Java, Python or Node are stopped at the first bait.** A `.jar` "game" double-clicked
  on the Desktop runs as `javaw.exe`, which is signed, so its first reads only counted as suspicious and it was
  stopped by sweep detection at the third app's data. Now a signed runtime running a script or `.jar` from your
  Desktop, Downloads or Temp folder is critical, like an unsigned program there: frozen the moment it opens
  the first bait. Scripts elsewhere (your projects, tools installed with npm or pip) are unchanged. Found by
  running a real Java stealer against v0.5.1.

## v0.5.1

- **Fix: the frozen popup's question was back to front.** It asked "Did you expect it to read this?" with
  *Yes = Kill it*, so answering honestly that you expected it killed the program. It now asks "Kill it?"
  (*Yes* kills it, *No* means it's yours), with the same reminder that games, mods, cheats and cracks never
  need to read your data.

## v0.5.0

A new look, and a setup that takes a minute.

- **Setup, rethought.** *Recommended* asks two things (phone alerts, automatic updates) and uses the
  recommended baits and response; *Customize* asks everything. A review screen shows what's about to
  happen before anything is installed. Running setup again offers *Keep my settings* (repair/upgrade in
  place) or *Change settings*; `aba configure` goes straight to changing them.
- **It ends with proof.** Setup sends a test to your phone when you've just set phone alerts up, then
  offers the safe test: a harmless fake stealer reads a bait and you watch ABA freeze it.
- **Clearer progress and a summary.** Install steps show what each one did, and the summary card shows
  what you're protected with and the three commands worth knowing.
- **One design everywhere.** A new wordmark, one colour palette (adapts to light terminals), and a
  status line at the top of the dashboard: *Protected*, *Needs attention*, *Not protected* or
  *Responding to a threat*. Alert lists show plain words ("frozen · internet cut") and short IDs, alert
  details wrap to the window, the network section groups connections by destination and hides local
  ones, and "What now" lists `trust`, `kill` and `resume` for that alert.
- **`aba --help`** groups commands by when you need them, most useful first.
- **The one-line installer** downloads quickly (no PowerShell progress bar), uses a fresh folder each time
  and removes it afterwards, explains what went wrong instead of dumping a PowerShell error, and makes
  `aba` work in the same window right away.
- Windows paths in setup no longer lose their backslashes.
- **Fix: a stealer could be frozen twice.** When Windows logged the read faster than instant freeze finished
  checking the program's signature, both detection paths froze it and raised an alert each; one "unfreeze"
  then left it suspended. Now only one path ever freezes a process: the event log waits for an instant
  decision in progress, and instant freeze stands down for a process the event log already froze.

## v0.4.0

Catching stealers that hide inside other programs, and trust that malware can't reuse.

- **Sweep detection.** A process that reads several different apps' baits within 2 minutes (your password
  files count as one; browsers, Discord, wallets… each count on their own) is stopped as a stealer, whatever
  it is: signed, trusted by you, or part of Windows. This catches stealers injected into a legitimate
  program, which look like that program to every identity check. With instant freeze it's frozen before it
  can open the third.
- **Injected-code check.** When a Windows program reads a bait, ABA looks inside it for a whole program
  running from memory that isn't backed by any file on disk, the footprint of process injection/hollowing.
  Found: critical, even if you trusted that program.
- **Windows programs are no longer trusted by default.** Before, any Microsoft-signed program under
  `C:\Windows` reading a bait was only noted, so a stealer hollowed into `AppLaunch.exe` or injected into
  `explorer.exe` raised no popup. Now Windows programs in your session are *suspicious* (Windows services and
  the preview pane stay quiet), and the .NET tools stealers hollow out most (AppLaunch, vbc, csc, jsc,
  aspnet_compiler, AddInProcess, cvtres, CasPol, ilasm) are critical, like RegAsm and MSBuild already were.
- **Trust is now as narrow as possible:**
  - covers only the bait(s) the program was seen reading;
  - unsigned programs are pinned to that exact file (SHA-256), not just its path;
  - script hosts and runtimes (`python.exe`, `powershell.exe`, `java.exe`…) are pinned to the exact command
    line, so trusting one script no longer trusts every script that runtime ever runs.
  Existing rules keep working as before (all baits).
- **The frozen popup asks the right question.** "Did you expect it to read this? Games, mods, cheats, cracks
  and "free" tools never need to, even ones you started yourself." Only signed programs can be trusted
  permanently in one click from it; anything else is unfrozen that once.
- **Repeat suppression no longer hides attacks:** script hosts/runtimes and critical alerts always notify.
- `aba ignore list` and `aba learn` show exactly what each rule covers.

## v0.3.0

- **One click to trust your own apps.** Every alert now asks "Is this program yours?". *It's mine* undoes
  whatever ABA did and stops alerting on that program (rule pinned to its path and publisher). The frozen
  popup's "It's mine" now trusts the program too, instead of only unfreezing it. New `aba trust <alert-id>`.
- **No more alert spam.** A program that keeps reading the same bait without being acted on pops up once
  every 12 hours, not on every launch. Everything is still in `aba alerts`.
- **Learning mode never leaves you unprotected.** Critical threats (unsigned programs from user folders,
  script hosts) are stopped from the first minute; learning only holds back the response to merely
  suspicious programs. Setup only asks about it when it changes something (Strict, custom), and you get a
  notification when it ends.
- **Far fewer false positives from developer tools.** `~/.aws/credentials` is read by every AWS SDK on
  startup (OpenCode, Claude Code, VS Code, Terraform…). Signed programs doing that are now only logged;
  unsigned programs, script hosts and runtimes still trip it.

## v0.2.0

- **Automatic updates.** Setup now asks whether to keep ABA up to date (default: yes). The service checks
  GitHub about once a day and only installs releases whose checksum list is signed with ABA's release key
  (ed25519) and whose download matches the signed hash. It rolls back if the new version doesn't start,
  never downgrades, and waits until any incident is resolved.
- `aba update` installs a new version by hand; `aba update --check` only looks.
- `aba install --auto-update=false` for unattended installs that shouldn't update themselves.
- The dashboard shows the running version and whether auto-update is on.
- Releases now include `SHA256SUMS.txt.sig`.
- Tested against a real Discord token stealer with Windows Defender off: frozen 158 ms after it read a fake
  Discord token ([video](docs/demo.mp4)).

**Upgrading from v0.1.0:** v0.1.0 can't update itself, so run the install command once more (your settings
are kept), and answer the new question about automatic updates.

## v0.1.0

First release: baits for 18 apps, instant freeze, Security-log backup detection, per-severity responses
(freeze, block, kill, isolate), phone alerts (ntfy, Discord, Pushover, email), canary tokens, learning mode,
full uninstall.
