# Third-party notices

sentient1 is a derivative of **A Better Antivirus (ABA)** by vulnix0x4 and the
Flytrap contributors: https://github.com/vulnix0x4/a-better-antivirus

The upstream MIT licence is preserved verbatim in `LICENSE`. The source examined
was supplied in `B:\.git2\utils\aba`; it was an extracted source directory without
Git metadata, so no upstream commit identity has been inferred. Historical
upstream documentation is retained under `docs/UPSTREAM-*` for provenance only.
The current behaviour is described in the root README and SECURITY documents.

Changes for sentient1 include its independent application/service identities,
native Windows dashboard, audit-first defaults, health assessment, reports,
recovery handling, alert-ID validation, delayed-event guard, and actual oplock
readiness accounting. Upstream remains responsible only for its original work.

Go dependencies are pinned in `go.mod` and verified by `go.sum`. They include
Charmbracelet terminal components, Cobra, Tailscale's Windows Filtering Platform
bindings, and golang.org/x Windows/system packages. The Windows desktop uses
Microsoft .NET 8 and Windows Forms. Dependency licence texts are included in the
release's `licenses` folder; the .NET desktop runtime is a separate prerequisite.
