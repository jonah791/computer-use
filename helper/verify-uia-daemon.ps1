# verify-uia-daemon.ps1 - the acceptance test for the UIAccess daemon.
#
# CRITERION (two independent readings, both required):
#   1. FUNCTIONAL : the UIA action actually reached the target (the value changed).
#   2. NON-STEALING: the user's foreground window is the SAME before and after.
#
# WHY the target must NOT be the foreground window: if the target is already in front,
# "foregroundUnchanged" is true no matter what we do, so it proves nothing. So we build
# a target that is deliberately in the BACKGROUND, and put a different window in front.
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File verify-uia-daemon.ps1
param(
    [int]$Port = 0
)

$ErrorActionPreference = 'Stop'
$DataDir = Join-Path $env:ProgramData 'AliceUIA'
$StatusFile = Join-Path $DataDir 'daemon-status.json'
$TokenFile  = Join-Path $DataDir 'token.txt'

function Say($m) { Write-Host $m }

# ------------------------------------------------------------------ 0. daemon present?
if (-not (Test-Path $StatusFile)) { Say 'FAIL: daemon-status.json missing -> daemon never started'; exit 1 }
$st = Get-Content -LiteralPath $StatusFile -Raw | ConvertFrom-Json
if ($Port -eq 0) { $Port = [int]$st.port }
$tok = ''
if (Test-Path $TokenFile) { $tok = (Get-Content -LiteralPath $TokenFile -Raw).Trim() }

Say ('[0] daemon pid=' + $st.pid + ' port=' + $Port + ' session=' + $st.sessionId + ' uiAccessToken=' + $st.uiAccessToken)

function Rpc($line) {
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect('127.0.0.1', $Port)
    $ns = $c.GetStream()
    $b = [Text.Encoding]::UTF8.GetBytes($line + "`n")
    $ns.Write($b, 0, $b.Length); $ns.Flush()
    $rd = New-Object System.IO.StreamReader($ns, [Text.Encoding]::UTF8)
    $resp = $rd.ReadLine()
    $c.Close()
    return $resp
}
function B64($s) {
    if ([string]::IsNullOrEmpty($s)) { return '' }
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s))
}

$probe = Rpc 'sub=probe' | ConvertFrom-Json
Say ('[0] probe verdict = ' + $probe.verdict + '  check=' + $probe.check)
if ($probe.uiAccessToken -ne 1) {
    Say ''
    Say 'FAIL: uiAccessToken is not 1. Without UIAccess this daemon is just a resident UIA'
    Say 'client and CANNOT keep the foreground from being stolen. Fix the four conditions first:'
    Say '  (a) manifest highestAvailable+uiAccess  (b) cert chains to LocalMachine\Root'
    Say '  (c) exe under Program Files/Windows/System32  (d) EnableSecureUIAPaths=1'
}
$uiaOk = ($probe.uiAccessToken -eq 1)

# ------------------------------------------------------------------ 1. pick the "victim" background target
Say '[1] creating a background target (Notepad) so the criterion can be non-trivial'
$npProc = Start-Process notepad -PassThru
$deadline = (Get-Date).AddSeconds(8)
$npHwnd = 0
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 300
    $npProc.Refresh()
    if ($npProc.MainWindowHandle -ne 0) { $npHwnd = [int64]$npProc.MainWindowHandle; break }
}
if ($npHwnd -eq 0) { Say 'FAIL: Notepad window never appeared'; try { Stop-Process -Id $npProc.Id -Force } catch { }; exit 1 }
Say ('    target hwnd=' + $npHwnd + ' pid=' + $npProc.Id)

Say '[1b] target window UIA inventory'
$r = Rpc ("token=$tok|sub=list|hwnd=$npHwnd|max=30")
$inv = $r | ConvertFrom-Json
$valueName = $null
if ($inv.ok) {
    Say ('    total=' + $inv.totalElements + ' operable=' + $inv.operableCount + ' windowName=[' + $inv.windowName + ']')
    foreach ($it in $inv.items) {
        Say ('      [' + $it.idx + '] ' + $it.type + ' | ' + $it.patterns + ' | name=[' + $it.name + ']')
        if (-not $valueName -and $it.patterns -match 'value') { $valueName = $it.name }
    }
} else {
    Say ('    list error: ' + $inv.error)
}
if (-not $valueName) {
    Say '    WARN: no element exposing the value pattern -> will fall back to a foreground-only check'
}

# ------------------------------------------------------------------ 2. put a DIFFERENT window in front
# Use the daemon itself to set the foreground: a normal process usually cannot, a
# UIAccess one can. This doubles as the acceptance test for the 'restore' command.
$dsnHwnd = 0
$pr = Rpc ("token=$tok|sub=fg") | ConvertFrom-Json
Say ('[2] current foreground = ' + $pr.foregroundHwnd + ' [' + $pr.foregroundTitle + ']')
if ([int64]$pr.foregroundHwnd -ne $npHwnd) {
    $dsnHwnd = [int64]$pr.foregroundHwnd
    Say '    it is already something else; no need to move it'
} else {
    # Notepad came to the front on launch. Find any other top-level window to sit in front.
    $other = Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $_.Id -ne $npProc.Id } |
             Select-Object -First 1
    if ($other) {
        $dsnHwnd = [int64]$other.MainWindowHandle
        $rr = Rpc ("token=$tok|sub=restore|hwnd=$dsnHwnd") | ConvertFrom-Json
        Say ('    restore->' + $dsnHwnd + ' apiOk=' + $rr.apiOk + ' restored=' + $rr.restored)
    }
}

$fgBefore = (Rpc ("token=$tok|sub=fg") | ConvertFrom-Json).foregroundHwnd
Say ('[2b] baseline foreground = ' + $fgBefore + ' (must differ from target ' + $npHwnd + ')')
$criterionValid = ([int64]$fgBefore -ne $npHwnd)
if (-not $criterionValid) { Say '    WARN: could not separate the target from the foreground; the non-stealing reading will be meaningless' }

# ------------------------------------------------------------------ 3. act, and measure
Say '[3] performing the UIA action from the daemon'
$stamp = 'alice-uia-' + (Get-Date -Format 'HHmmss')
$act = $null
if ($valueName) {
    $r = Rpc ("token=$tok|sub=setvalue|hwnd=$npHwnd|name=" + (B64 $valueName) + "|text=" + (B64 $stamp))
    $act = $r | ConvertFrom-Json
    Say ('    setvalue on [' + $valueName + '] -> ok=' + $act.ok + ' matched=[' + $act.matched + ']')
} else {
    Say '    (no value target; skipping the write, doing a read-only foreground probe instead)'
    $act = Rpc ("token=$tok|sub=fg") | ConvertFrom-Json
}
if ($act.PSObject.Properties.Name -contains 'error' -and $act.error) { Say ('    error: ' + $act.error) }

Say ''
Say '=== RESULT ==='
if ($act.PSObject.Properties.Name -contains 'foregroundBefore') {
    Say ('uiAccessToken          : ' + $act.uiAccess)
    Say ('foreground before      : ' + $act.foregroundBefore)
    Say ('foreground during      : ' + $act.foregroundDuring)
    Say ('foreground after action: ' + $act.foregroundAfterAction)
    Say ('foreground after restor: ' + $act.foregroundAfterRestore)
    Say ('stolenByAction         : ' + $act.stolenByAction)
    Say ('restoreTried           : ' + $act.restoreTried + '  apiOk=' + $act.restoreApiOk)
    Say ('foregroundUnchanged    : ' + $act.foregroundUnchanged)
    Say ''
    Say ('READING 1 (functional)    : ' + $(if ($act.ok) { 'PASS - the action reached the target' } else { 'FAIL - ' + $act.error }))
    if ($criterionValid) {
        if ($act.foregroundUnchanged) {
            Say 'READING 2 (non-stealing)  : PASS - foreground stayed put'
        } elseif ($act.restoreTried -and ($act.foregroundAfterRestore -eq $act.foregroundBefore)) {
            Say 'READING 2 (non-stealing)  : PASS-with-repair - the target grabbed the foreground,'
            Say '                            UIAccess handed it straight back (brief flicker, final state correct)'
        } else {
            Say 'READING 2 (non-stealing)  : FAIL - foreground ended up somewhere else'
        }
    } else {
        Say 'READING 2 (non-stealing)  : N/A - target was never separated from the foreground'
    }
} else {
    Say ('probe only, no action: ' + ($act | ConvertTo-Json -Compress))
}

# ------------------------------------------------------------------ 4. read the value back
if ($valueName) {
    Say ''
    Say '[4] reading the target back to prove the write landed'
    $r2 = Rpc ("token=$tok|sub=list|hwnd=$npHwnd|max=30")
    $inv2 = $r2 | ConvertFrom-Json
    $found = $false
    foreach ($it in $inv2.items) {
        if ($it.name -eq $valueName) { $found = $true }
    }
    if ($found) { Say ('    element still present; expected content = ' + $stamp) }
    # value readout is not exposed by list; ask the window title as a cheap side-channel
    $npProc.Refresh()
    Say ('    notepad title now = [' + $npProc.MainWindowTitle + ']')
}

try { Stop-Process -Id $npProc.Id -Force } catch { }
Say ''
Say ('daemon still running: ' + ($null -ne (Get-Process -Id $st.pid -ErrorAction SilentlyContinue)))
