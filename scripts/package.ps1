[CmdletBinding()]
param([string]$Version = '1.1.0', [switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Use a numeric major.minor.patch version.' }
    if (!$SkipBuild) { & (Join-Path $PSScriptRoot 'build.ps1') -Version $Version }
    foreach ($name in @('sentient1.exe','sentient1-Desktop.exe','SHA256SUMS.txt')) {
        if (!(Test-Path (Join-Path $projectRoot "dist\$name"))) { throw "Missing build output: $name" }
    }
    $engineVersion = & .\dist\sentient1.exe --version
    if ($LASTEXITCODE -ne 0 -or $engineVersion -ne "sentient1 $Version") { throw 'Built engine version does not match package version.' }
    $desktopVersion = (Get-Item .\dist\sentient1-Desktop.exe).VersionInfo.ProductVersion.Split('+')[0]
    if ($desktopVersion -ne $Version) { throw 'Built desktop version does not match package version.' }
    $releaseDir = Join-Path $projectRoot 'releases'
    New-Item -ItemType Directory -Force $releaseDir | Out-Null
    $archivePath = Join-Path $releaseDir "sentient1_${Version}_Windows_x64_Source.zip"
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stream = [IO.File]::Open($archivePath, [IO.FileMode]::Create)
    $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create)
    try {
        $dist = Join-Path $projectRoot 'dist'
        Get-ChildItem $dist -Recurse -File | Sort-Object FullName | Where-Object {
            $_.Extension -ne '.pdb' -and $_.Name -notin @('desktop-smoke-test.txt','desktop-ui-test.txt')
        } | ForEach-Object {
            $relative = [IO.Path]::GetRelativePath($dist, $_.FullName).Replace('\','/')
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $_.FullName, $relative, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
        $sourceFiles = @()
        foreach ($directory in @('cmd','desktop','docs','internal','scripts','.github')) {
            $sourceFiles += Get-ChildItem (Join-Path $projectRoot $directory) -Recurse -File
        }
        foreach ($name in @('README.md','CHANGELOG.md','CONTRIBUTING.md','SECURITY.md','THIRD-PARTY-NOTICES.md','LICENSE','go.mod','go.sum','.editorconfig','.gitignore','.gitattributes')) {
            $sourceFiles += Get-Item (Join-Path $projectRoot $name)
        }
        $sourceFiles | Sort-Object FullName | ForEach-Object {
            $relative = [IO.Path]::GetRelativePath($projectRoot, $_.FullName).Replace('\','/')
            if ($relative -notmatch '^desktop/(bin|obj)/' -and $_.Extension -notin @('.exe','.zip','.pdb')) {
                [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $_.FullName, ('source/' + $relative), [IO.Compression.CompressionLevel]::Optimal) | Out-Null
            }
        }
    } finally { $archive.Dispose(); $stream.Dispose() }
    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $([IO.Path]::GetFileName($archivePath))" | Set-Content (Join-Path $releaseDir 'SHA256SUMS.txt') -Encoding ascii
    Write-Output "Packaged $archivePath"
    Write-Output "SHA256 $hash"
} finally { Pop-Location }
