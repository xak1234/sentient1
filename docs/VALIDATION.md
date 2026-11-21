# sentient1 1.0.0 validation

Windows x64, 21 November 2026.

| Check | Result |
|---|---|
| `scripts/build.ps1 -Version 1.0.0` | Passed, 00:17:29 UTC |
| `gofmt -l ./cmd ./internal` | No unformatted files |
| `go vet ./...` | Passed |
| `go test ./...` | Passed; administrator-only tests are skipped without the explicit environment variable |
| .NET 8 Release publish | Passed with nullable checks and warnings treated as errors |
| `dotnet format --verify-no-changes --no-restore --severity warn` | Passed |
| `TestBaitReadIsDetected`, administrator integration run | Passed; 704.649 ms observed delivery |
| `TestBlockProgram`, administrator integration run | Passed; private temporary curl blocked then restored |
| Native desktop smoke test | Passed; real form constructed and real engine snapshot parsed |
| Dashboard visual inspection | Passed; actual Windows window, readable status, toolbar and tabs |
| CLI version / JSON status / manual update check | Passed |
| Offline HTML report | Generated successfully |

Minimal reproducible runtime check from `dist`:

```powershell
.\sentient1.exe --version
# sentient1 1.0.0

$status = .\sentient1.exe status --json | ConvertFrom-Json
$status.product
# sentient1
$status.assessment.title
# Not installed (before the user completes setup)
```

The original upstream baseline failed `TestOwnReadIsNotBlamedOnOthers` on this
host. The readiness change removed its fixed-delay assumption; the final
sentient1 oplock package passed along with the other packages. This does not
establish that timing inference is reliable on all Windows versions or loads;
it remains off by default.

No real malware was executed. Full installation, long-running protection,
whole-host isolation and uninstall have not been validated end-to-end in a VM.
The dashboard was built and tested without installing a persistent monitor.
