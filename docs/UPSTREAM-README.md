<div align="center">

# A Better Antivirus

**It's not an antivirus. It's a better one.**

Catch infostealers in the act. ABA plants fake passwords, wallets and app data<br>
that only malware would ever read, and freezes whatever touches them.

[![Release](https://img.shields.io/github/v/release/vulnix0x4/a-better-antivirus?style=flat-square&color=30d158)](https://github.com/vulnix0x4/a-better-antivirus/releases/latest)
[![Tests](https://img.shields.io/github/actions/workflow/status/vulnix0x4/a-better-antivirus/ci.yml?branch=main&style=flat-square&label=tests)](https://github.com/vulnix0x4/a-better-antivirus/actions/workflows/ci.yml)
[![Downloads](https://img.shields.io/github/downloads/vulnix0x4/a-better-antivirus/total?style=flat-square&color=blue)](https://github.com/vulnix0x4/a-better-antivirus/releases)
[![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?style=flat-square)](#install)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)](LICENSE)

<a href="docs/demo.mp4"><img src="docs/demo.gif" alt="A real Discord token stealer, Windows Defender off: ABA freezes it the moment it opens a bait" width="800"></a>

<sub>A real Discord token stealer with Windows Defender off. It went for a fake Discord token and was frozen 158 ms later.<br><a href="docs/demo.mp4">Watch the full video with sound (47 s)</a></sub>

</div>

## Install

In PowerShell:

```powershell
irm https://raw.githubusercontent.com/vulnix0x4/a-better-antivirus/main/install.ps1 | iex
```

It downloads the latest release for your PC, checks it against the release's `SHA256SUMS.txt`, and starts the setup ([read the script first](install.ps1) if you like). Setup takes about a minute:

- **Recommended** asks just two things, phone alerts and automatic updates, and uses sensible defaults for the rest. **Customize** lets you pick every bait and response.
- If you set up phone alerts, it sends a test notification so you know they work.
- It ends by offering a **safe test**: a harmless fake stealer reads a bait and you watch ABA freeze it.
- Afterwards `aba` works in the same PowerShell window.

<p align="center"><img src="docs/setup.png" alt="The end of setup: every step ticked, then a summary card saying you're protected" width="720"></p>

<details>
<summary><b>Other ways to install</b></summary>

**Test VM, no questions asked** (strict mode, no learning period):

```powershell
$env:ABA_ARGS = 'install --yes --preset strict --learning 0'; irm https://raw.githubusercontent.com/vulnix0x4/a-better-antivirus/main/install.ps1 | iex
```

**By hand:** download `aba_<version>_windows_amd64.exe` (or `arm64`) from [Releases](https://github.com/vulnix0x4/a-better-antivirus/releases/latest), check its SHA-256 against `SHA256SUMS.txt`, and run it with `install`. Releases aren't code-signed yet, so SmartScreen may warn you: verify the hash first, then use *More info → Run anyway*.

> Only ever paste `irm … | iex` commands from sources you trust: it's also how many stealers get installed ("paste this to fix your PC"). This one is in the open, short, and refuses to run a download whose checksum doesn't match.

</details>

Despite the name, **keep Windows Defender on.** Antivirus tries to stop malware from running; ABA is the tripwire for when something gets past it, and that's the part antivirus is bad at.

## Why this works

Infostealers (Lumma, RedLine, Vidar, StealC…) are the most common malware on personal PCs. They sweep your browsers, wallets, Discord/Telegram sessions and documents, zip it all up and upload it, usually within seconds. Most of them **collect first and upload at the end**, and collecting means opening files in known places. ABA puts tripwires in exactly those places.

- **Fake files** where file grabbers look: `passwords.txt` on the Desktop, in Documents and in your home folder, a wallet recovery phrase, 2FA backup codes, a KeePass database.
- **Fake app data for apps you don't use**: Opera, Vivaldi and Yandex browser profiles (with saved passwords and cookies), MetaMask, Exodus, Electrum and Atomic wallets, Telegram sessions, Discord tokens, FileZilla servers, AWS keys. Nothing legitimate ever reads these, because the app isn't installed, so the signal is extremely clean. ABA checks what you actually have installed and never fakes data for those apps. If you install one later, ABA notices and quietly retires that decoy.
- **Canary tokens** (optional): the fake AWS keys and a link in `passwords.txt` are real [canarytokens.org](https://canarytokens.org) tokens. If a stealer gets your data and someone *uses* them later, you get an email, even if your PC was never online to tell you.

It catches stealers by **what they do**, not by recognising the file, so it works on brand-new ones no antivirus has a signature for yet.

```
> aba test

 A harmless copy of ABA in your Temp folder is about to read passwords.txt on the Desktop,
 exactly the way a stealer would. Nothing leaves your PC and your network isn't touched.

 ✓ Caught      critical: unsigned program running from a user-writable folder: typical of stealers
 ✓ Frozen      72 ms after it opened the bait, before it could read a byte
 ✓ Alerted     popup on your desktop, and your phone (ntfy)
 ✓ Cleaned up  the fake stealer was killed and deleted
```

## How it works

```
 stealer opens a bait
        │
        ├─► instant freeze: ABA holds every bait with an oplock, so Windows tells it
        │   the moment the file is opened (see below). Typically frozen in ~0.1 s.
        │
        └─► backup: NTFS audit rule ──► Security event 4663 ──► ABA service (SYSTEM)
            (Windows delivers these in a few ms to ~1 s)        │
           1. instant verdict from path/name ───┤ unsigned + Temp/AppData/Downloads? script host?
           2. freeze the process tree ──────────┤ (before it can upload)
           3. verify the code signature ────────┤ signed legit app? → unfreeze, just note it
           4. collect forensics while frozen ───┤ command line, parents, hash, connections
           5. block / kill / isolate ───────────┤ as configured
           6. alert ────────────────────────────┘ desktop popup + toast + phone
```

- **Instant freeze** (on by default, `aba instant on|off`): ABA holds an exclusive *opportunistic lock* on every bait. When a program opens one, Windows pauses it inside the open and tells ABA immediately. ABA notes which threads just got stuck, lets go, and the one that wakes at that exact instant is the opener: identified precisely, never guessed. If it's suspicious it's frozen right away, typically ~0.1 s after the open (72–151 ms in CI), instead of waiting for the event log. To stay safe it only ever acts on ordinary non-admin programs in your session, never on system processes or on ABA itself, and if more than one program wakes at once it doesn't guess.
- **Detection backup** uses Windows' own file auditing (an audit rule on each bait, read through the Security event log). No kernel driver, no background scanning, no CPU use while idle. Malware running as you can neither see nor remove the audit rules.
- **Severity** is automatic. Malware without admin rights can't write to `Program Files` or `Windows`, and stealers are almost always unsigned binaries in user-writable folders or abuse script hosts like PowerShell or mshta. So:

  | Reader | Severity |
  |---|---|
  | Anything that goes through **several apps' data** within 2 minutes (a sweep) | **critical** |
  | A Windows program running **injected code** (code that isn't from any file on disk) | **critical** |
  | Unsigned program in Temp, AppData, Downloads, Desktop… | **critical** |
  | PowerShell, cmd, mshta, rundll32, wscript, and .NET tools stealers hide in (RegAsm, AppLaunch, vbc, MSBuild…) | **critical** |
  | Java, Python, Node… running a script or `.jar` from your Desktop, Downloads or Temp (a "game" you double-clicked) | **critical** |
  | Signed app in a user folder, scripting runtimes (Python, Node, Java), other Windows programs in your session, network share reads | **warn** |
  | Signed, installed software (Program Files), Windows services, the preview pane | **info** |
  | Defender, Windows Search, your trust rules | ignored |

- **Behaviour beats identity.** Stealers often hide inside a legitimate program (process injection / hollowing), so *who* opened a bait can lie. *What* it opened can't: a real app only ever touches its own data, a stealer grabs everything it knows in seconds. So a process that reads several different apps' baits (your password files count as one, browsers, Discord, wallets… each count on their own) is stopped as a stealer whatever it claims to be: signed, trusted by you, or part of Windows. Only Defender, Windows Search and programs you explicitly allow to read everything (a backup tool) are exempt. And when a Windows program reads a bait, ABA looks inside it for a whole program running from memory that isn't backed by any file, the footprint of injected code.

- **Responses** per severity. Presets:

  | Preset | Critical | Warn |
  |---|---|---|
  | Alert only | notify | notify |
  | **Balanced** (default) | freeze + block that program's internet | notify |
  | Strict | freeze + block + isolate the PC | freeze |

  Isolation uses the Windows Filtering Platform (the same engine enterprise "isolate device" uses). It survives reboots so malware can't wait it out, and it still lets ABA's own phone alert through. `aba release` undoes everything.

## Everyday use

```
aba              live dashboard
aba test         simulate a stealer safely and watch it get caught
aba alerts       what touched your baits (aba alerts show <id> for everything)
aba doctor       check everything is armed (--fix to repair)
aba learn        trust several of your own apps at once
```

When something trips:

```
aba trust <id>   it's yours: undo everything and stop alerting about it
aba kill <id>    it's malware: end what the alert froze (it stays cut off)
aba resume <id>  not sure: let it run again, without trusting it
aba release      undo all responses: network back, everything unfrozen/unblocked
```

Setup:

```
aba configure    change baits, response, learning mode, phone alerts, updates, canary tokens
aba update       check for a new version and install it (--check to only look)
aba bait list | show <id> | add <path> | remove <id> | catalog
aba ignore list | add <pattern> [--signer X] | remove <n>
aba instant [on|off]
aba phone test
aba uninstall [--purge]
```

**Don't open your bait files**: that's a read. Use `aba bait show <id>` instead; it prints the content without touching the file. If you do open one, Windows adds it to *Recent files*, and apps like Copilot then read it (that's how we found out). ABA removes those shortcuts automatically.

## When it's one of your apps

Every alert asks whether that program should be reading that bait. One click on *It's mine* undoes anything ABA did (unfreezes it, restores its internet) and stops alerting on it. Trust is kept as narrow as possible, so malware can't reuse it:

- it covers **only the bait(s) the program was seen reading**: code injected into a trusted app that goes after anything else is still caught;
- a signed program is pinned to its folder **and** its code-signing publisher;
- an unsigned program is pinned to **that exact file** (its SHA-256), not its path, since anything can be dropped at the same path later;
- a script host or runtime (`python.exe`, `powershell.exe`, `java.exe`…) is pinned to **the exact command line**: trusting your script never trusts every script;
- a Windows program that went through several apps' data is never trusted permanently, only unfrozen that once.

When something is **frozen**, the popup asks "Kill it?" and reminds you that games, mods, cheats and cracks never need to read this, rather than asking "is it yours?" (you *did* start that cracked game yourself), and only signed programs can be trusted in one click; anything else is unfrozen that once (`aba trust <id>` in a terminal still trusts it, pinned to the file). A program that keeps touching a bait without you answering only pops up once every 12 hours, except script hosts and anything critical; the rest goes to `aba alerts`.

**Learning mode** (Strict and custom setups, 3 days by default): critical threats are stopped from minute one, but merely suspicious programs only alert, so you can mark your own apps before Strict starts freezing them. You get a notification when it ends. `aba learn` lists everything that tripped, to trust several at once.

## Phone alerts

ntfy (free, no account), Discord webhook, Pushover or email (SMTP with TLS). Secrets are stored DPAPI-encrypted in a file only SYSTEM and Administrators can read. ABA remembers the alert server's IP addresses, so alerts still get out when the PC is isolated and DNS is blocked.

## Updates

Setup asks whether to keep ABA up to date automatically (you can change it any time with `aba configure`, or run `aba update` yourself).

When it's on, the service checks GitHub about once a day. A new version is only installed if:

1. the release's `SHA256SUMS.txt` carries a valid **ed25519 signature** from ABA's release key (the public key is built into ABA), and
2. the downloaded `.exe` matches its hash in that signed list.

So a swapped release file, a compromised mirror or a proxy can't get code onto your PC. The update swaps the binaries, restarts the service, and **rolls back automatically** if the new version doesn't start. It never downgrades, ignores pre-releases, and never updates in the middle of an incident (while something is frozen or the PC is isolated).

## Honest limitations

- **It's a tripwire, not a shield.** It catches stealers that go looking for files. A stealer that only grabs your real browser data and never touches a bait won't trip it.
- **Speed.** With instant freeze a stealer is frozen about 0.1 s after it opens a bait (it gets the fake bait contents, not your real data). Without it, ABA waits for the event log: a few ms to about 1 s. A stealer that uploads each item the moment it reads it may get something out first; freezing stops whatever it hasn't sent yet.
- **Instant freeze is deliberately cautious.** It skips programs running as administrator and anything it can't pinpoint with certainty; those are still caught by the event-log path, just a little later.
- **Admin malware.** Malware running as administrator can stop the service, clear the audit policy or remove filters. ABA alerts if auditing is switched off, but it can't defend against an attacker who already owns the machine.
- **Injection is judged by its results, not watched as it happens.** Seeing one process write code into another needs a kernel driver or Microsoft's protected-antivirus signing, which ABA doesn't have. It catches injected stealers by what they read (sweeps) and, inside Windows programs, by the injected code they leave in memory. A stealer injected into an app you trusted that reads *only* the one bait you trusted that app with would get through; nothing real works that way, but it's possible. The memory check skips programs that legitimately generate code (.NET, Java, browsers), and newer tricks that disguise injected code as a file on disk (module stomping, process ghosting) aren't detected by it; the sweep rule still applies to them.
- **Desktop popups need you to be signed in.** Detections are always logged and phone alerts always go out, and responses happen either way.
- **Some legit software reads files** (backup, sync, search tools). One click on *It's mine* handles that. A backup tool that copies your whole AppData looks like a sweep; allow it to read everything with `aba ignore add "<path>" --signer <publisher>` (or *It's mine* on the sweep alert, for signed programs).
- **`~/.aws/credentials` is read by every AWS SDK** (OpenCode, Claude Code, VS Code, Terraform…), so a *signed* program reading it is only logged. Unsigned programs, script hosts and runtimes still trip it, and the other baits are unaffected.
- **Low profile, not hidden.** The service is called "File Access Monitor" so it doesn't advertise itself to malware that checks for honeypots, but it's fully visible to you.

## What gets changed on your PC

| What | Where | Undone by uninstall |
|---|---|---|
| Program | `C:\Program Files\File Access Monitor` | ✓ |
| Service | `FileAccessMonitor` (LocalSystem, auto-start) | ✓ |
| Data, alerts, logs | `C:\ProgramData\FileAccessMonitor` | alerts kept unless `--purge` |
| Audit policy | "Audit File System: Success" | ✓ restored to what it was |
| Baits | your folders + fake app folders | ✓ (files you made yourself are kept) |
| Firewall filters | WFP provider "A Better Antivirus" (only while responding) | ✓ |
| PATH | adds the program folder | ✓ |

**What goes over the network:** phone alerts you set up; if you opt in, canary token creation (your email is sent to canarytokens.org); and with automatic updates on, a daily request to `api.github.com` for the latest release. Nothing else, no telemetry.

## Building

```
go test ./...
go build -o dist/aba.exe ./cmd/aba
```

Admin-only integration tests (real audit rules, Security log, WFP) run in CI, or locally from an elevated shell with `ABA_INTEGRATION=1 go test ./internal/integration/`. CI also runs a full end-to-end install → fake stealers → freeze/kill/isolate → uninstall on a real Windows machine for every push. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Found a way to bypass or abuse ABA? Please report it privately: see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
