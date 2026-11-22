[CmdletBinding()]
param([string]$Version = '1.2.1', [string]$OutputDirectory = 'dist')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$buildOutput = if ([IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory } else { Join-Path $projectRoot $OutputDirectory }
[IO.Directory]::CreateDirectory($buildOutput) | Out-Null
Push-Location $projectRoot
try {
    if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Use a numeric major.minor.patch version.' }
    $unformatted = @(gofmt -l ./cmd ./internal)
    if ($unformatted.Count -gt 0) { throw ('Run gofmt on: ' + ($unformatted -join ', ')) }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go vet failed.' }
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed.' }
    go build -trimpath -ldflags "-s -w -X main.version=$Version" -o (Join-Path $buildOutput 'sentient1.exe') ./cmd/sentient1
    if ($LASTEXITCODE -ne 0) { throw 'Go build failed.' }
    dotnet publish .\desktop\sentient1.Desktop.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true "-p:Version=$Version" -o $buildOutput
    if ($LASTEXITCODE -ne 0) { throw 'Desktop build failed.' }
    dotnet format .\desktop\sentient1.Desktop.csproj --verify-no-changes --no-restore --severity warn
    if ($LASTEXITCODE -ne 0) { throw 'Desktop formatting/analyzer checks failed.' }
    Copy-Item .\README.md,.\CHANGELOG.md,.\LICENSE,.\THIRD-PARTY-NOTICES.md,.\SECURITY.md -Destination $buildOutput -Force
    Copy-Item .\docs -Destination $buildOutput -Recurse -Force
    $licenseDir = Join-Path $buildOutput 'licenses'
    New-Item -ItemType Directory -Path $licenseDir -Force | Out-Null
    $modules = go list -m -f '{{.Path}}|{{.Dir}}' all
    if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate dependency licences.' }
    foreach ($line in $modules) {
        $parts = $line -split '\|',2
        if ($parts.Length -ne 2 -or !$parts[1] -or $parts[0] -eq 'github.com/xak1234/sentient1') { continue }
        $prefix = $parts[0] -replace '[^A-Za-z0-9._-]','_'
        Get-ChildItem -LiteralPath $parts[1] -File | Where-Object { $_.Name -match '^(LICENSE|COPYING|NOTICE)' } | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $licenseDir ($prefix + '-' + $_.Name)) -Force
        }
    }
    Get-ChildItem $buildOutput -Filter *.exe | ForEach-Object {
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    } | Set-Content (Join-Path $buildOutput 'SHA256SUMS.txt') -Encoding ascii
    Write-Output "Built sentient1 $Version in $buildOutput"
} finally { Pop-Location }
