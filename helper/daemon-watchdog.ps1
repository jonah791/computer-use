# daemon-watchdog.ps1 - keep cu-uia-daemon alive, and start it at logon.
#
# WHY a scheduled task and not a thread inside the daemon: a watchdog that lives in the
# process it watches dies with it. WHY a scheduled task and not a startup shortcut: the
# daemon's manifest is highestAvailable+uiAccess, so launching it from a Medium-IL context
# blocks on the UAC prompt (measured: 122367 ms, "操作已被用户取消"). A task registered
# with /rl highest starts it at High IL with no prompt at all.
#
# Registered as:  schtasks /create /tn "AliceUIA Daemon" /sc minute /mo 1 /rl highest ...
# so this script runs every minute AND is the thing that starts the daemon at logon
# (an already-running daemon simply makes each run a no-op).
#
# Exit codes: 0 = healthy or fixed, 1 = could not fix (needs a human).

$ErrorActionPreference = 'Continue'

$DataDir    = Join-Path $env:ProgramData 'AliceUIA'
$StatusFile = Join-Path $DataDir 'daemon-status.json'
$LogFile    = Join-Path $DataDir 'watchdog.log'
$ExePath    = Join-Path $env:ProgramFiles 'AliceUIA\cu-uia-daemon.exe'

function Log([string]$msg) {
    $line = (Get-Date).ToString('s') + '  ' + $msg
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
}

function Trim-Log {
    # keep the watchdog log from growing without bound
    try {
        if (Test-Path $LogFile) {
            $size = (Get-Item $LogFile).Length
            if ($size -gt 512KB) {
                $tail = Get-Content -LiteralPath $LogFile -Tail 500
                Set-Content -LiteralPath $LogFile -Value $tail -Encoding UTF8
                Log 'log trimmed'
            }
        }
    } catch { }
}

function Test-DaemonTcp([int]$port, [string]$token) {
    # A live pid is not enough - the process can be up but wedged. Ask it to answer.
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $ar = $c.BeginConnect('127.0.0.1', $port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne(1200)) { try { $c.Close() } catch { }; return $false }
        $c.EndConnect($ar)
        $ns = $c.GetStream()
        $ns.ReadTimeout = 3000
        $b = [Text.Encoding]::UTF8.GetBytes("sub=probe`n")
        $ns.Write($b, 0, $b.Length); $ns.Flush()
        $rd = New-Object System.IO.StreamReader($ns, [Text.Encoding]::UTF8)
        $resp = $rd.ReadLine()
        $c.Close()
        return (-not [string]::IsNullOrEmpty($resp)) -and ($resp -match '"tool"\s*:\s*"cu-uia-daemon"')
    } catch {
        return $false
    }
}

Trim-Log

# ------------------------------------------------------------------ 1. is it up?
$needStart = $false
$reason = ''
$port = 8444

if (-not (Test-Path $ExePath)) {
    Log ("FAIL: daemon binary missing at " + $ExePath)
    exit 1
}

if (-not (Test-Path $StatusFile)) {
    $needStart = $true
    $reason = 'no status file'
} else {
    try {
        $st = Get-Content -LiteralPath $StatusFile -Raw | ConvertFrom-Json
        if ($st.port) { $port = [int]$st.port }
        $alive = $false
        if ($st.pid) { $alive = $null -ne (Get-Process -Id ([int]$st.pid) -ErrorAction SilentlyContinue) }
        if (-not $alive) {
            $needStart = $true
            $reason = "pid $($st.pid) not alive"
        } else {
            # guard against racing a daemon that is still booting: if the status file
            # was written very recently, give it the benefit of the doubt
            $ageSec = ((Get-Date) - (Get-Item $StatusFile).LastWriteTime).TotalSeconds
            if (Test-DaemonTcp $port '') {
                exit 0    # healthy, nothing to say
            }
            if ($ageSec -lt 20) {
                Log ("pid " + $st.pid + " alive but not answering yet (" + [int]$ageSec + "s since start) - waiting")
                exit 0
            }
            $needStart = $true
            $reason = "pid $($st.pid) alive but TCP probe failed on port $port"
        }
    } catch {
        $needStart = $true
        $reason = "status file unreadable: " + $_.Exception.Message
    }
}

# ------------------------------------------------------------------ 2. fix it
if (-not $needStart) { exit 0 }

Log ("restarting daemon: " + $reason)
try {
    # kill a wedged instance first (its pid is reported in the reason)
    if ($reason -match 'pid (\d+) alive') {
        $oldPid = [int]$Matches[1]
        try { Stop-Process -Id $oldPid -Force -ErrorAction Stop; Log ("killed wedged pid " + $oldPid) } catch { }
        Start-Sleep -Milliseconds 500
    }
    $p = Start-Process -FilePath $ExePath -ArgumentList @('--port', "$port") -WindowStyle Hidden -PassThru
    Log ("spawned pid " + $p.Id)
} catch {
    Log ("spawn FAILED: " + $_.Exception.Message)
    exit 1
}

# ------------------------------------------------------------------ 3. verify the fix
$deadline = (Get-Date).AddSeconds(15)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
    if (Test-DaemonTcp $port '') {
        $st2 = $null
        try { $st2 = Get-Content -LiteralPath $StatusFile -Raw | ConvertFrom-Json } catch { }
        Log ("recovered: pid=" + $(if ($st2) { $st2.pid } else { '?' }) + " uiAccess=" + $(if ($st2) { $st2.uiAccessToken } else { '?' }))
        exit 0
    }
}

Log 'FAIL: daemon did not answer within 15s after restart'
exit 1
