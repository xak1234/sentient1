<#
.SYNOPSIS
  Full end-to-end test of sentient1 on a disposable Windows machine.

.DESCRIPTION
  Installs SENTIENT1, runs fake stealers against it and checks every response:
  freeze, per-program block, kill, resume + ignore, release, strict-mode
  isolation (with a phone alert sent *while* isolated), bait repair, decoy
  retirement, custom baits, and a complete uninstall.

  DO NOT run this on a PC you care about: it isolates the network for a few
  seconds and changes system settings. It's meant for CI runners.
#>
param(
    [string]$Aba = (Join-Path $PSScriptRoot '..\dist\sentient1.exe'),
    [string]$Medium = (Join-Path $PSScriptRoot '..\dist\medium.exe')
)

$ErrorActionPreference = 'Stop'
$Aba  = (Resolve-Path $Aba).Path
$Medium = (Resolve-Path $Medium).Path
$data = Join-Path $env:ProgramData 'sentient1Monitor'
$installDir = Join-Path $env:ProgramFiles 'sentient1 Monitor'
$fsGuid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
$topic = 'sentient1-ci-' + [guid]::NewGuid().ToString('N').Substring(0, 16)
$started = Get-Date
$script:failures = 0

# Live progress outside the machine: if the runner becomes unreachable (it has,
# twice, with no log), the last steps and service log lines are still readable
# at https://ntfy.sh/<progress topic>. Test output only; nothing secret.
$progress = if ($env:GITHUB_RUN_ID) { "sentient1-ci-progress-$($env:GITHUB_RUN_ID)" } else { $null }
function Report([string]$m) {
    if (-not $progress) { return }
    try { Invoke-RestMethod -Method Post -Uri "https://ntfy.sh/$progress" -Body $m -TimeoutSec 5 | Out-Null } catch {}
}
if ($progress) {
    Write-Host "Live progress: https://ntfy.sh/$progress"
    # Background reporter: ships new service.log lines every 3 s.
    Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList '-NoProfile', '-Command', @"
`$seen = 0
while (`$true) {
  Start-Sleep 3
  `$f = '$data\service.log'
  if (Test-Path `$f) {
    `$lines = @(Get-Content `$f)
    if (`$lines.Count -gt `$seen) {
      `$new = (`$lines[`$seen..(`$lines.Count - 1)] | Where-Object { `$_ -notmatch 'woke at once' }) -join "`n"
      try { Invoke-RestMethod -Method Post -Uri 'https://ntfy.sh/$progress' -Body ('LOG ' + `$new) -TimeoutSec 5 | Out-Null; `$seen = `$lines.Count } catch {}
    }
  }
}
"@ | Out-Null
}

function Step($n) { Write-Host "`n=== $n ===" -ForegroundColor Cyan; Report "=== $n" }
function Ok($m)   { Write-Host "  ok  $m" -ForegroundColor Green; Report "ok $m" }
function Fail($m) {
    Write-Host "  FAIL $m" -ForegroundColor Red
    Report "FAIL $m"
    # Never leave the runner isolated or anything frozen: it would go offline
    # and GitHub could neither cancel the job nor show its log.
    $r = Start-Process -FilePath $Aba -ArgumentList 'release' -NoNewWindow -PassThru
    if (-not $r.WaitForExit(60000)) { $r.Kill() }
    if (Test-Path "$data\service.log") { Write-Host '--- service.log (tail) ---'; Get-Content "$data\service.log" -Tail 120 }
    if (Test-Path "$data\crash.log") { Write-Host '--- crash.log ---'; Get-Content "$data\crash.log" -Tail 200 }
    exit 1
}

# Safety net while the machine is isolated: a separate process that runs
# `sentient1 release` after $seconds even if this script dies or hangs.
function ReleaseWatchdog([int]$seconds) {
    $topicArg = if ($progress) { $progress } else { '' }
    $script = @"
Start-Sleep $seconds
function Say(`$m) { if ('$topicArg') { try { Invoke-RestMethod -Method Post -Uri 'https://ntfy.sh/$topicArg' -Body ('WATCHDOG ' + `$m) -TimeoutSec 5 | Out-Null } catch {} } }
for (`$i = 1; `$i -le 4; `$i++) {
  `$out = & '$Aba' release 2>&1 | Out-String
  & curl.exe -s -o NUL --max-time 8 https://www.microsoft.com
  if (`$LASTEXITCODE -eq 0) { Say "release attempt `$i restored the network: `$out"; exit }
  if (`$i -eq 2) { sc.exe stop sentient1Monitor | Out-Null; Start-Sleep 5 }
  Start-Sleep 10
}
Say 'could not restore the network'
"@
    Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList '-NoProfile', '-Command', $script -PassThru
}
function Check($cond, $m) { if ($cond) { Ok $m } else { Fail $m } }
# Every sentient1 call gets a deadline: a hang fails fast with the service log.
function Aba {
    $argline = ($args | ForEach-Object { if ("$_" -match '\s') { '"' + $_ + '"' } else { "$_" } }) -join ' '
    $p = Start-Process -FilePath $Aba -ArgumentList $argline -NoNewWindow -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit(120000)) {
        Write-Host "  sentient1 $argline is still running after 2 minutes; frozen processes:" -ForegroundColor Red
        if (Test-Path "$data\state.json") { (Get-Content "$data\state.json" -Raw | ConvertFrom-Json).frozen | Format-Table | Out-Host }
        $p.Kill()
        Fail "sentient1 $argline hung"
    }
    if ($p.ExitCode) { Fail "sentient1 $argline exited $($p.ExitCode)" }
}

function Alerts { if (Test-Path "$data\alerts") { Get-ChildItem "$data\alerts\*.json" | Sort-Object Name | ForEach-Object { Get-Content $_ -Raw | ConvertFrom-Json } } }
function WaitFor([scriptblock]$cond, [int]$seconds = 20) {
    $t = Get-Date
    while (((Get-Date) - $t).TotalSeconds -lt $seconds) {
        $r = & $cond
        if ($r) { return $r }
        Start-Sleep -Milliseconds 300
    }
    return $null
}
function AlertFor([int]$procId, [int]$seconds = 20) { WaitFor { Alerts | Where-Object { $_.process.pid -eq $procId } | Select-Object -Last 1 } $seconds }
function State { Get-Content "$data\state.json" -Raw | ConvertFrom-Json }
function Did($alert, $action) { [bool]($alert.actions | Where-Object { $_.action -eq $action -and $_.ok }) }

# A fake stealer: a copy of sentient1.exe in Temp (unsigned, user-writable -> critical)
# that reads a bait and then waits around.
# Like real stealers it runs as the normal user at medium integrity (not admin;
# scripts/medium does that from the elevated runner), and a few random bytes
# make its hash differ from SENTIENT1's, so it isn't recognised as SENTIENT1 itself.
function Stealer([string]$name, [string]$bait, [switch]$Again) {
    $exe = Join-Path $env:TEMP "$name.exe"
    if (-not $Again) {   # -Again: run the same file again (same fingerprint)
        # A previous copy may still be exiting (Stop-Process doesn't wait).
        for ($i = 0; ; $i++) {
            try { Copy-Item $Aba $exe -Force -ErrorAction Stop; break }
            catch { if ($i -ge 30) { throw }; Start-Sleep -Milliseconds 300 }
        }
        [IO.File]::AppendAllText($exe, [guid]::NewGuid().ToString())
    }
    $procId = & $Medium $exe test-reader $bait
    if ($LASTEXITCODE -or -not $procId) { Fail "fake stealer $name didn't start" }
    $p = Get-Process -Id ([int]$procId) -ErrorAction SilentlyContinue
    if (-not $p) { Fail "fake stealer $name exited immediately" }
    return $p
}
function IsSuspended([int]$procId) {
    $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if (-not $p) { return $false }
    foreach ($t in $p.Threads) {
        try { if ($t.ThreadState -ne 'Wait' -or $t.WaitReason -ne 'Suspended') { return $false } } catch { return $false }
    }
    return $true
}
function Online {
    foreach ($u in "https://www.microsoft.com", "https://github.com") { & curl.exe -s -o NUL --max-time 8 $u; if ($LASTEXITCODE -eq 0) { return $true } }
    return $false
}
function WfpRules {
    $f = Join-Path $env:TEMP 'wfp.xml'
    netsh wfp show filters file="$f" | Out-Null
    (Select-String -Path $f -Pattern '<name>SENTIENT1: ' -AllMatches).Matches.Count
}
# ntfy returns one JSON object per line; read the raw text (Invoke-RestMethod
# would auto-parse a single line into an object).
function NtfyMessages {
    $raw = (Invoke-WebRequest "https://ntfy.sh/$topic/json?poll=1&since=all" -UseBasicParsing).Content
    if ($raw -is [byte[]]) { $raw = [Text.Encoding]::UTF8.GetString($raw) }
    $raw -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object event -eq 'message'
}
function AuditFS { (auditpol /get /subcategory:"$fsGuid" /r | ConvertFrom-Csv).'Inclusion Setting' }

# ---------------------------------------------------------------------------
Step 'Baseline'
$auditBefore = AuditFS
Ok "audit policy before install: $auditBefore"
Check (WaitFor { Online } 45) 'machine is online'

Step 'Install (balanced, no learning, ntfy phone alerts)'
Aba install --yes --preset balanced --learning 0 --ntfy-topic $topic
Check ((Get-Service sentient1Monitor).Status -eq 'Running') 'service running'
$st = State
$desktopBait = ($st.baits.'desktop-passwords'.files | Select-Object -First 1).path
Check (Test-Path $desktopBait) "desktop bait planted: $desktopBait"
Check (@($st.baits.PSObject.Properties).Count -ge 10) "$(@($st.baits.PSObject.Properties).Count) baits planted"
Check ((AuditFS) -match 'Success') 'file auditing on'
$cfg = Get-Content (Join-Path $data 'config.json') -Raw | ConvertFrom-Json
Check ($cfg.autoUpdate -eq $true) 'auto-update on by default'
Check ($cfg.version -ge 2) 'config is version 2'
Aba update --check
Aba doctor
Aba phone test
Check (WaitFor { NtfyMessages | Where-Object title -match 'test alert' } 20) 'phone test alert arrived on ntfy'

Step 'Built-in safe test'
Aba test

Step 'Real stealer: frozen, blocked, then killed'
$s1 = Stealer 'stealer1' $desktopBait
$a1 = AlertFor $s1.Id
Check ($a1) "alert raised ($($a1.id))"
Check ($a1.tier -eq 'critical') "tier critical: $($a1.summary)"
Check (Did $a1 'freeze') "froze it ($($a1.latencyMs) ms after the read, delivery $($a1.deliveryMs) ms)"
Check (Did $a1 'block-program') 'blocked its internet'
Check (WaitFor { IsSuspended $s1.Id } 5) 'process really is suspended'
Check ((WfpRules) -gt 0) 'WFP block rules present'
Check ((State).frozen.pid -contains $s1.Id) 'state lists it as frozen'
$sess = (Get-Process -Id $s1.Id -ErrorAction SilentlyContinue).SessionId
Ok "stealer ran in session $sess as a normal (medium-integrity) process"
if ($sess -eq 0) {
    Ok 'instant freeze deliberately skips session 0 (services); caught via the event log instead'
} else {
    Check ($a1.instant -eq $true) "instant freeze: caught the moment it opened the bait (frozen $($a1.latencyMs) ms after the open)"
}
$tree = @($s1.Id) + @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($s1.Id)" | ForEach-Object ProcessId)
# Only processes that still exist count (the `sentient1 test` reader is killed by design).
$innocent = @((State).frozen | Where-Object { $tree -notcontains $_.pid -and (Get-Process -Id $_.pid -ErrorAction SilentlyContinue) })
Check ($innocent.Count -eq 0) "no innocent process frozen (frozen: $(((State).frozen.image) -join ', '))"
Select-String -Path "$data\service.log" -Pattern 'instant' | ForEach-Object { "  log: " + $_.Line } | Out-Host
Aba alerts show $a1.id
Aba kill $a1.id
Check (WaitFor { -not (Get-Process -Id $s1.Id -ErrorAction SilentlyContinue) } 10) 'killed'
Check (WaitFor { NtfyMessages | Where-Object { $_.message -match $a1.id } } 30) 'critical alert reached the phone (ntfy)'

Step 'A signed, legit program reading a bait is let through'
$legit = Join-Path $env:TEMP 'legit-curl.exe'   # Microsoft-signed (catalog), so "warn": notify only
Copy-Item "$env:SystemRoot\System32\curl.exe" $legit -Force
$legitOut = Join-Path $env:TEMP 'legit-out.txt'
$sw = [Diagnostics.Stopwatch]::StartNew()
$c = Start-Process -FilePath $legit -ArgumentList '-s', '-o', "`"$legitOut`"", ("file:///" + ($desktopBait -replace '\\', '/')) -NoNewWindow -PassThru
$null = $c.Handle
if (-not $c.WaitForExit(20000)) {
    $verdict = Alerts | Where-Object { $_.process.pid -eq $c.Id } | Select-Object -Last 1
    Fail "signed curl was still stuck after 20 s; SENTIENT1's verdict: $($verdict.tier) / $($verdict.process.signature | ConvertTo-Json -Compress) / $($verdict.summary)"
}
$sw.Stop()
Check ($c.ExitCode -eq 0 -and (Get-Item $legitOut).Length -gt 0) "it got the file ($((Get-Item $legitOut).Length) bytes, paused $($sw.ElapsedMilliseconds) ms in total)"
Check (-not ((State).frozen | Where-Object { $_.image -like '*legit-curl*' })) 'it was not frozen'

Step 'False positive: resume + ignore'
$s2 = Stealer 'mytool' $desktopBait
$a2 = AlertFor $s2.Id
Check ($a2 -and (Did $a2 'freeze')) 'second reader frozen'
Aba resume $a2.id --ignore
Check (WaitFor { -not (IsSuspended $s2.Id) } 5) 'resumed'
Check ((& $Aba ignore list | Out-String) -match 'mytool') 'ignore rule added'
Stop-Process -Id $s2.Id -Force -ErrorAction SilentlyContinue
$before = @(Alerts).Count
$s2b = Stealer 'mytool' $desktopBait -Again
Start-Sleep -Seconds 6
Check (@(Alerts).Count -eq $before) 'ignored program no longer alerts'
Check (-not (IsSuspended $s2b.Id)) 'ignored program not frozen'
Stop-Process -Id $s2b.Id -Force -ErrorAction SilentlyContinue
# It's unsigned, so the rule is pinned to that exact file: anything else
# dropped at the same path later is still caught.
$s2c = Stealer 'mytool' $desktopBait
$a2c = AlertFor $s2c.Id
Check ($a2c -and $a2c.tier -eq 'critical' -and (Did $a2c 'freeze')) 'a different file at the trusted path is still caught'
Aba kill $a2c.id
Aba ignore remove 1

Step 'Learning mode still stops critical; one-click trust (the popup''s "It''s mine")'
Aba install --yes --preset balanced --learning 3 --ntfy-topic $topic
$s5 = Stealer 'devtool' $desktopBait
$a5 = AlertFor $s5.Id
Check ($a5 -and (Did $a5 'freeze')) 'critical reader frozen during learning mode'
Aba trust $a5.id
Check (WaitFor { -not (IsSuspended $s5.Id) } 5) 'trust unfroze it'
Check ((& $Aba ignore list | Out-String) -match 'devtool') 'trust added an ignore rule'
Stop-Process -Id $s5.Id -Force -ErrorAction SilentlyContinue
$before = @(Alerts).Count
$s5b = Stealer 'devtool' $desktopBait -Again
Start-Sleep -Seconds 6
Check (@(Alerts).Count -eq $before) 'trusted program no longer alerts'
Stop-Process -Id $s5b.Id -Force -ErrorAction SilentlyContinue
# Trust covers only the bait it was seen reading.
$discordBait = ($st.baits.discord.files | Where-Object audit | Select-Object -First 1).path
$s5c = Stealer 'devtool' $discordBait -Again
$a5c = AlertFor $s5c.Id
Check ($a5c -and (Did $a5c 'freeze')) 'the trusted program going after a different bait is still frozen'
Aba kill $a5c.id
Aba ignore remove 1
Aba install --yes --preset balanced --learning 0 --ntfy-topic $topic

Step 'A Windows program going through several apps'' data is stopped (how an injected stealer looks)'
# find.exe is part of Windows and signed by Microsoft: one bait read by it is
# only "suspicious". Reading your files, Discord and a browser in a row is a sweep.
$sweepBaits = @($desktopBait, $discordBait, ($st.baits.brave.files | Where-Object audit | Select-Object -First 1).path)
$findExe = "$env:SystemRoot\System32\find.exe"
$fp = & $Medium -raw $findExe ("'$findExe' 'zz-not-there' " + (($sweepBaits | ForEach-Object { "'$_'" }) -join ' '))
if ($LASTEXITCODE -or -not $fp) { Fail "find.exe didn't start" }
$a6 = WaitFor { Alerts | Where-Object { $_.process.pid -eq [int]$fp -and $_.tier -eq 'critical' } | Select-Object -Last 1 } 20
Check ($a6) "find.exe sweeping 3 apps' baits is critical: $($a6.summary)"
Check (@($a6.verdict.swept).Count -ge 3) "swept: $($a6.verdict.swept -join ', ')"
if ((Get-Process -Id ([int]$fp) -ErrorAction SilentlyContinue).SessionId -gt 0) {
    Check ((Did $a6 'freeze') -and (WaitFor { IsSuspended ([int]$fp) } 5)) 'frozen before it could read the third'
    Aba kill $a6.id
}
Check (Did $a6 'block-program') 'its internet is cut'

Step 'Release everything'
Aba release
$st = State
Check ((-not $st.frozen) -and (-not $st.blocked)) "nothing frozen or blocked (frozen=$($st.frozen | ConvertTo-Json -Compress) blocked=$($st.blocked | ConvertTo-Json -Compress))"
Check ((WfpRules) -eq 0) 'all WFP rules gone'

Step 'Strict mode: isolation, with the phone alert sent while isolated'
Aba install --yes --preset strict --learning 0 --ntfy-topic $topic
$watchdog = ReleaseWatchdog 90   # network comes back even if this script dies
$s3 = Stealer 'stealer3' $desktopBait
$a3 = AlertFor $s3.Id
Check ($a3 -and (Did $a3 'isolate')) 'PC isolated'
Check ((State).isolation) 'state shows isolation'
Check (-not (Online)) 'other programs are offline'
Start-Sleep -Seconds 4   # let the service push the phone alert through the isolation
Aba release
Check (WaitFor { Online } 60) 'back online after release'
Stop-Process -Id $watchdog.Id -Force -ErrorAction SilentlyContinue
Check (WaitFor { NtfyMessages | Where-Object { $_.message -match $a3.id } } 30) 'phone alert got out while isolated'
Stop-Process -Id $s3.Id -Force -ErrorAction SilentlyContinue

Step 'Back to balanced; deleted bait gets repaired'
Aba install --yes --preset balanced --learning 0 --ntfy-topic $topic
Remove-Item $desktopBait -Force
Check (WaitFor { Alerts | Where-Object { $_.kind -eq 'delete' -and $_.baits.path -contains $desktopBait } } 20) 'deletion alerted'
Aba doctor --fix
Check (WaitFor { Test-Path $desktopBait } 30) 'bait recreated'

Step 'Decoy retires when the real app shows up'
$st = State
$decoy = @('vivaldi', 'yandex', 'opera', 'exodus') | Where-Object { $st.baits.$_ -and $st.baits.$_.status -eq 'ok' } | Select-Object -First 1
if ($decoy) {
    $markers = @{
        vivaldi = "$env:LOCALAPPDATA\Vivaldi\Application\vivaldi.exe"
        yandex  = "$env:LOCALAPPDATA\Yandex\YandexBrowser\Application\browser.exe"
        opera   = "$env:LOCALAPPDATA\Programs\Opera\opera.exe"
        exodus  = "$env:LOCALAPPDATA\exodus\Exodus.exe"
    }
    $m = $markers[$decoy]
    New-Item -ItemType Directory -Force (Split-Path $m) | Out-Null
    Set-Content $m 'pretend app' -Encoding ascii
    Aba doctor --fix
    Check (WaitFor { (State).baits.$decoy.status -eq 'retired' } 30) "$decoy decoy retired"
    $first = ((State).baits.$decoy.files | Select-Object -First 1).path
    Check (-not (Test-Path $first)) 'its fake files are gone'
    Remove-Item (Split-Path $m) -Recurse -Force
} else { Ok 'no decoy available to retire on this runner (skipped)' }

Step 'Custom bait'
$custom = Join-Path $env:USERPROFILE 'Documents\bank logins.txt'
Aba bait add $custom
Check (Test-Path $custom) 'custom bait created'
$cid = ((State).baits.PSObject.Properties | Where-Object { $_.Value.files[0].path -eq $custom }).Name
Check ($cid) "registered as $cid"
if ($decoy) { Check ((State).baits.$decoy.status -eq 'retired') "retired $decoy decoy stays retired after changing baits" }
$s4 = Stealer 'stealer4' $custom
Check (AlertFor $s4.Id) 'reading the custom bait alerts'
Aba release
Stop-Process -Id $s4.Id -Force -ErrorAction SilentlyContinue
Aba bait remove $cid
Check (-not (Test-Path $custom)) 'custom bait removed'

Step 'Read-only commands'
$before = @(Alerts).Count
Aba bait show desktop-passwords
Start-Sleep -Seconds 3
Check (@(Alerts).Count -eq $before) '`bait show` prints the bait without tripping it'
Aba bait list
Aba bait catalog
Aba alerts
Aba status --once
Aba learn --stop
Aba doctor

Step 'Turn auto-update off unattended'
Aba install --yes --preset balanced --learning 0 --auto-update=false
Check ((Get-Content (Join-Path $data 'config.json') -Raw | ConvertFrom-Json).autoUpdate -eq $false) '--auto-update=false turns it off'

Step 'Uninstall'
Aba uninstall --yes --purge
Check (-not (Get-Service sentient1Monitor -ErrorAction SilentlyContinue)) 'service removed'
Check (-not (Test-Path $desktopBait)) 'baits removed'
Check (-not (Test-Path "$env:APPDATA\Opera Software")) 'fake app folders removed'
Check (-not (Test-Path $data)) 'data folder purged'
Check (-not (Test-Path $installDir) -or @(Get-ChildItem $installDir -Recurse -File).Count -eq 0) 'program files removed'
Check ((WfpRules) -eq 0) 'no WFP rules left'
Check ((AuditFS) -eq $auditBefore) "audit policy restored ($auditBefore)"
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check (-not ($machinePath -split ';' | Where-Object { $_ -eq $installDir })) 'removed from PATH'
Check (Online) 'still online'

Write-Host "`nALL END-TO-END CHECKS PASSED in $([int]((Get-Date) - $started).TotalSeconds)s" -ForegroundColor Green
