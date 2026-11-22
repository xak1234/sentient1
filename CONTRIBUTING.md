# Working on sentient1

sentient1 is an independent MIT-licensed derivative of ABA. Use Go 1.27.4 and .NET SDK
8.0 on Windows x64. Run `scripts/build.ps1` before distributing changes. Keep the
MIT licence and third-party notices. Use a disposable VM for installation,
isolation and broad end-to-end tests. Do not re-enable automatic updates until
an independently controlled and verified signing channel exists.

See `docs/REVIEW.md` for the initial review and `README.md` for the module map.

The `main` branch runs Windows CI for formatting, vet, ordinary tests and the
native desktop build. Selective audit/WFP integration checks run on the disposable
runner. Broad install/isolation tests remain an explicit VM-only operation.

To package a tested build, run `scripts/package.ps1 -SkipBuild`.
Omit `-SkipBuild` to rebuild first. Attach the ZIP and `releases/SHA256SUMS.txt` to
a versioned GitHub release; do not commit compiled binaries or local monitor data.
