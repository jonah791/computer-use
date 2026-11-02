# build-uia-daemon.ps1 - build, sign and install cu-uia-daemon.exe (the UIAccess resident worker)
#
# WHY THIS SHAPE (measured 2026-10-26 on this machine):
#   UIAccess requires manifest level="highestAvailable" (asInvoker is rejected with
#   ERROR_ELEVATION_REQUIRED even from an elevated parent). A highestAvailable binary
#   therefore needs elevation on EVERY launch. Launching it from the Medium-IL DSH
#   process blocked on the UAC prompt: "操作已被用户取消", 122367 ms, no output.
#   => per-call spawning is dead. One admin start, then TCP.
#
# PHASES
#   Phase A (normal user):  powershell -NoProfile -ExecutionPolicy Bypass -File build-uia-daemon.ps1
#                           compile + sign + verify (needs the code-signing cert in CurrentUser\My)
#   Phase B (ADMIN shell):  ... -File build-uia-daemon.ps1 -Install
#                           install root cert (idempotent) -> copy to Program Files ->
#                           run --probe-only -> verify uiAccessToken=1 -> start the daemon
#   Stop:                   ... -File build-uia-daemon.ps1 -Stop
#   Status:                 ... -File build-uia-daemon.ps1 -Status
#
# The daemon listens on 127.0.0.1:8444 (walks upward if busy) and publishes its state to
#   C:\ProgramData\AliceUIA\daemon-status.json ; the shared secret lives in token.txt.

param(
    [switch]$Install,
    [switch]$Stop,
    [switch]$Status,
    [string]$Thumbprint = '',
    [string]$Subject = 'CN=Alice UIAccess Test',
    [int]$Port = 8444
)

$ErrorActionPreference = 'Stop'

$Here       = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcPath    = Join-Path $Here 'uia-daemon\Daemon.cs'
$Work       = 'E:\alice\_tmp_review\uia-daemon'
$ExeName    = 'cu-uia-daemon.exe'
$InstallDir = Join-Path $env:ProgramFiles 'AliceUIA'
$DataDir    = Join-Path $env:ProgramData 'AliceUIA'
$StatusFile = Join-Path $DataDir 'daemon-status.json'
$ProbeFile  = Join-Path $DataDir 'probe-result.json'
$TokenFile  = Join-Path $DataDir 'token.txt'

New-Item -ItemType Directory -Path $Work -Force | Out-Null

function Step($n, $msg) { Write-Host ("[{0}] {1}" -f $n, $msg) }

function Read-JsonFile($path) {
    if (-not (Test-Path $path)) { return $null }
    try { return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } catch { return $null }
}

# ------------------------------------------------------------------ status / stop
if ($Status) {
    $st = Read-JsonFile $StatusFile
    if (-not $st) {
        Write-Host 'daemon-status.json not found - daemon has never started'
        exit 1
    }
    Write-Host '--- daemon-status.json ---'
    $st | ConvertTo-Json -Depth 4
    $alive = $false
    try { $alive = $null -ne (Get-Process -Id $st.pid -ErrorAction Stop) } catch { $alive = $false }
    Write-Host ("pid alive = " + $alive)
    $probe = Read-JsonFile $ProbeFile
    if ($probe) { Write-Host ("last probe verdict = " + $probe.verdict + " (uiAccessToken=" + $probe.uiAccessToken + ")") }
    exit 0
}

if ($Stop) {
    $st = Read-JsonFile $StatusFile
    if (-not $st) { Write-Host 'nothing to stop (no status file)'; exit 0 }
    $stopped = $false
    try {
        $tok = ''
        if (Test-Path $TokenFile) { $tok = (Get-Content -LiteralPath $TokenFile -Raw).Trim() }
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect('127.0.0.1', [int]$st.port)
        $ns = $client.GetStream()
        $req = "token=$tok|sub=stop"
        $bytes = [Text.Encoding]::UTF8.GetBytes($req + "`n")
        $ns.Write($bytes, 0, $bytes.Length)
        $ns.Flush()
        Start-Sleep -Milliseconds 400
        $client.Close()
        Step 1 'stop request sent'
        $stopped = $true
    } catch {
        Step 1 ("stop via TCP failed: " + $_.Exception.Message)
    }
    Start-Sleep -Milliseconds 500
    try {
        $p = Get-Process -Id $st.pid -ErrorAction SilentlyContinue
        if ($p) { Step 2 'process still alive after stop request -> killing'; Stop-Process -Id $st.pid -Force }
        else { Step 2 'process exited' }
    } catch { }
    Remove-Item $StatusFile -ErrorAction SilentlyContinue
    Write-Host 'stopped.'
    exit 0
}

# ------------------------------------------------------------------ resolve certificate
if (-not $Thumbprint) {
    $c = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
         Where-Object { $_.Subject -eq $Subject } | Select-Object -First 1
    if ($c) { $Thumbprint = $c.Thumbprint }
}
if (-not $Thumbprint) {
    Step 1 'no code-signing cert found -> creating self-signed'
    $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject `
            -KeyUsage DigitalSignature -CertStoreLocation 'Cert:\CurrentUser\My' `
            -NotAfter (Get-Date).AddYears(2) -KeyExportPolicy Exportable
    $Thumbprint = $c.Thumbprint
} else {
    $c = Get-Item "Cert:\CurrentUser\My\$Thumbprint"
}
Step 1 ("certificate: " + $c.Subject + "  thumb=" + $Thumbprint)

# ------------------------------------------------------------------ resolve UIAutomation assemblies
# Do NOT hardcode GAC version folders: ask the runtime where they actually live.
Step 2 'resolving UIAutomation assembly paths'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName WindowsBase

$refClient = [System.Windows.Automation.AutomationElement].Assembly.Location
$refTypes  = [System.Windows.Automation.AutomationIdentifier].Assembly.Location
$refWB     = [System.Windows.Rect].Assembly.Location
foreach ($r in @($refClient, $refTypes, $refWB)) {
    if (-not (Test-Path $r)) { throw "assembly not resolved: $r" }
    Write-Host ("    ref: " + $r)
}

# ------------------------------------------------------------------ compile
Step 3 'compiling with embedded manifest'
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { throw 'csc.exe not found' }

$manifest = @'
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="highestAvailable" uiAccess="true" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />
    </application>
  </compatibility>
</assembly>
'@
$manPath = Join-Path $Work 'app.manifest'
Set-Content -LiteralPath $manPath -Value $manifest -Encoding UTF8

$exePath = Join-Path $Work $ExeName
if (Test-Path $exePath) { Remove-Item $exePath -Force }

& $csc /nologo /target:exe /optimize+ "/win32manifest:$manPath" "/out:$exePath" `
      "/r:$refClient" "/r:$refTypes" "/r:$refWB" $SrcPath
if ($LASTEXITCODE -ne 0) { throw "compile failed (csc exit $LASTEXITCODE)" }
if (-not (Test-Path $exePath)) { throw 'compile produced no exe' }
Step 3 ("compiled: $exePath (" + (Get-Item $exePath).Length + " bytes)")

# ------------------------------------------------------------------ sign
Step 4 'signing'
$sig = Set-AuthenticodeSignature -Certificate $c -FilePath $exePath -TimestampServer '' -ErrorAction Stop
Step 4 ("signature status: " + $sig.Status + " / " + $sig.StatusMessage)

$cerPath = Join-Path $Work 'alice-uia.cer'
Export-Certificate -Cert $c -FilePath $cerPath -Type CERT | Out-Null
Step 4 ("cert exported: $cerPath")

if (-not $Install) {
    Write-Host ''
    Write-Host '=== Phase A complete (non-elevated) ==='
    Write-Host 'Expected signature status: Valid (a self-signed chain may read "UnknownError"'
    Write-Host 'only on a machine where the root is not installed yet).'
    Write-Host ''
    Write-Host 'Next: open an ADMIN PowerShell and run:'
    Write-Host ("  powershell -NoProfile -ExecutionPolicy Bypass -File `"" + $PSCommandPath + "`" -Install -Thumbprint " + $Thumbprint)
    exit 0
}

# ------------------------------------------------------------------ PHASE B (admin)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'REFUSED: -Install requires an elevated (Administrator) shell.'
    exit 1
}

Step 5 'installing root certificate into LocalMachine\Root (idempotent)'
try {
    $existing = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $Thumbprint }
    if ($existing) { Step 5 'root already trusted' }
    else {
        Import-Certificate -FilePath $cerPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
        Step 5 'root certificate installed'
    }
} catch {
    Step 5 ("install root FAILED: " + $_.Exception.Message)
}

Step 6 'stopping any running instance before replacing the binary'
$prev = Read-JsonFile $StatusFile
if ($prev) {
    try { Stop-Process -Id $prev.pid -Force -ErrorAction SilentlyContinue } catch { }
    Start-Sleep -Milliseconds 400
}

Step 7 ("copying to secure location: " + $InstallDir)
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
$installedExe = Join-Path $InstallDir $ExeName
Copy-Item -LiteralPath $exePath -Destination $installedExe -Force
Step 7 ("installed: $installedExe")

Step 8 'signature check on the installed copy'
$sig2 = Get-AuthenticodeSignature -FilePath $installedExe
Write-Host ("    status=" + $sig2.Status)
if ($sig2.Status -ne 'Valid') {
    Write-Host '    !! signature is not Valid - UIAccess will NOT activate !!'
    Write-Host ("    reason: " + $sig2.StatusMessage)
}

Step 9 'running --probe-only from the secure location (this is where UIAccess is proven)'
Remove-Item $ProbeFile -ErrorAction SilentlyContinue
try {
    Start-Process -FilePath $installedExe -ArgumentList '--probe-only' -Wait -ErrorAction Stop
} catch {
    Step 9 ("probe launch FAILED: " + $_.Exception.Message)
}
Start-Sleep -Milliseconds 400
if (Test-Path $ProbeFile) {
    Write-Host '    --- probe-result.json ---'
    $pj = Read-JsonFile $ProbeFile
    if ($pj) { $pj | ConvertTo-Json -Depth 4 | ForEach-Object { Write-Host ("    " + $_) } }
    else { Get-Content -LiteralPath $ProbeFile | ForEach-Object { Write-Host ("    " + $_) } }
} else {
    Write-Host '    !! probe-result.json NOT produced !!'
    Write-Host ('    Double-click in Explorer to force the ShellExecute path: ' + $installedExe)
}

Step 10 'starting the resident daemon'
Remove-Item $StatusFile -ErrorAction SilentlyContinue
$proc = Start-Process -FilePath $installedExe -ArgumentList @('--port', "$Port") -WindowStyle Hidden -PassThru
Step 10 ("spawned pid=" + $proc.Id)

$deadline = (Get-Date).AddSeconds(12)
$st = $null
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 400
    $st = Read-JsonFile $StatusFile
    if ($st) { break }
}
if ($st) {
    Write-Host '    --- daemon-status.json ---'
    $st | ConvertTo-Json -Depth 4 | ForEach-Object { Write-Host ("    " + $_) }
    Write-Host ''
    Write-Host ("RESULT: uiAccessToken=" + $st.uiAccessToken + "  verdict=" + $st.verdict + "  port=" + $st.port)
} else {
    Write-Host '    !! daemon-status.json NOT produced - daemon failed to start !!'
    Write-Host ("    check the log: " + (Join-Path $DataDir 'daemon.log'))
}

Write-Host ''
Write-Host 'Done. From now on the DSH side talks TCP to this daemon; no more elevation prompts.'

# ------------------------------------------------------------------ Step 11: watchdog task
# WHY: a watchdog living inside the process it watches dies with it, and a plain startup
# shortcut cannot launch a highestAvailable+uiAccess binary from a Medium-IL context
# (measured: UAC prompt hangs 122367 ms then self-cancels). A scheduled task registered
# with RunLevel=Highest is the only launcher that starts it at High IL with no prompt.
# LogonType=Interactive keeps it in the USER session - Session 0 has no desktop, so a
# daemon there would see zero windows and still report healthy.
Step 11 'registering the watchdog scheduled task (runs at logon, repeats every 3 minutes)'
$Watchdog = Join-Path $PSScriptRoot 'daemon-watchdog.ps1'
if (-not (Test-Path $Watchdog)) {
    Step 11 ("SKIPPED: watchdog script not found at " + $Watchdog)
} else {
    $taskName = 'AliceUIA Daemon Watchdog'
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $Watchdog + '"')
        $trigLogon = New-ScheduledTaskTrigger -AtLogOn
        $trigRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
            -RepetitionInterval (New-TimeSpan -Minutes 3) `
            -RepetitionDuration (New-TimeSpan -Days 3650)
        $principal = New-ScheduledTaskPrincipal -UserId ($env:USERDOMAIN + '\' + $env:USERNAME) `
            -RunLevel Highest -LogonType Interactive
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigLogon, $trigRepeat) `
            -Principal $principal -Settings $settings -Force | Out-Null
        Step 11 ("registered: " + $taskName)

        Step 11 'proving the task actually runs the watchdog (cold sample, not just registration)'
        Start-ScheduledTask -TaskName $taskName
        Start-Sleep -Seconds 6
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        $wlog = Join-Path $DataDir 'watchdog.log'
        Write-Host ('    lastRunTime=' + $info.LastRunTime + '  lastResult=' + $info.LastTaskResult)
        if (Test-Path $wlog) {
            Write-Host '    --- watchdog.log ---'
            Get-Content -LiteralPath $wlog -Tail 6 | ForEach-Object { Write-Host ('    ' + $_) }
        } else {
            Write-Host '    (watchdog.log not written yet - first run may still be starting)'
        }
    } catch {
        Step 11 ("FAILED to register the task: " + $_.Exception.Message)
        Write-Host '    Manual fallback (elevated cmd):'
        Write-Host ('      schtasks /create /tn "' + $taskName + '" /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"' + $Watchdog + '\"" /sc minute /mo 3 /rl highest /f')
    }
}

Write-Host ''
Write-Host 'All set. Verify anytime with:'
Write-Host ('  powershell -NoProfile -File "' + $PSCommandPath + '" -Status')
Write-Host ('  powershell -NoProfile -File "' + $PSCommandPath + '" -Stop')
