# cu-helper.ps1 — computer-use 的执行层（每次调用独立进程，无状态）
#
# 调用约定：
#   powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File cu-helper.ps1 <command> [args...]
# 输出：单行 JSON（UTF-8）
#
# 设计约束（本机实测）：
#   1. Defender ASR 规则 01443614-… 禁止运行「全新未签名 exe」⇒ 不做 exe，改 Add-Type 内存编译
#   2. PowerShell 5.1 默认 DPI-unaware（看到逻辑坐标 1707x1067）⇒ 必须 SetProcessDPIAware()
#      声明后一切坐标 = 物理像素 = 截图像素（实测 665×1.5=998）
#   3. 注入类命令必须验靶（安全闸 I1）：2026-09-15 事故——测试脚本未验靶即注入，
#      39 个字符被送进主人正在使用的浏览器窗口。闸放在本文件内（原子），不放在调用方。
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

function Emit($obj) { ($obj | ConvertTo-Json -Compress -Depth 8) }

function Fail($stage, $message) {
  Emit @{ ok = $false; stage = $stage; error = "$message" }
  exit 1
}

# ---- 加载原生层 ----
$nativePath = Join-Path $PSScriptRoot 'CuNative.cs'
if (-not (Test-Path $nativePath)) { Fail 'load' "CuNative.cs not found at $nativePath" }
try {
  if (-not ('CuNative' -as [type])) {
    Add-Type -TypeDefinition (Get-Content -Raw -LiteralPath $nativePath) -Language CSharp | Out-Null
  }
  $script:dpiAware = [CuNative]::SetProcessDPIAware()
} catch { Fail 'load' $_.Exception.Message }

# ---- 参数解析：位置参数 + --flag ----
function Split-Flags([string[]]$argv) {
  $pos = @(); $flags = @{}
  if ($null -eq $argv) { return @{ pos = $pos; flags = $flags } }
  for ($i = 0; $i -lt $argv.Count; $i++) {
    $a = $argv[$i]
    switch ($a) {
      '--expect' { $flags.expect = [string]$argv[$i + 1]; $i++ }
      '--expect-hwnd' { $flags.expectHwnd = [int64]$argv[$i + 1]; $i++ }
      '--allow-any' { $flags.allowAny = $true }
      '--scale' { $flags.scale = [double]$argv[$i + 1]; $i++ }
      '--region' { $flags.region = [string]$argv[$i + 1]; $i++ }
      '--window' { $flags.window = [int64]$argv[$i + 1]; $i++ }
      '--limit' { $flags.limit = [int]$argv[$i + 1]; $i++ }
      '--local' { $flags.local = $true }
      '--force' { $flags.force = $true }
      default { $pos += $a }
    }
  }
  return @{ pos = $pos; flags = $flags }
}

function B64Str([string]$s) {
  if ([string]::IsNullOrEmpty($s)) { return '' }
  return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s))
}

# ---- UIAccess 常驻通道（2026-10-26）----
# 为什么必须走它：UIAccess 程序的清单必须是 highestAvailable（asInvoker 实测报
# ERROR_ELEVATION_REQUIRED），所以每次起进程都要提权；从 Medium IL 起会挂在 UAC 上
# （实测 launch=FAILED / 122367ms / 无输出）。⇒ 一次提权常驻，之后走本地 TCP。
# 它同时解决「动作抢前台」：UIAccess 进程调用 SetForegroundWindow 能成功，所以
# 目标即使抢了前台也能立刻交还（restore）。本进程内实现做不到这一点。
function Resolve-UiaDaemon {
  $statusFile = Join-Path $env:ProgramData 'AliceUIA\daemon-status.json'
  if (-not (Test-Path $statusFile)) { return $null }
  try {
    $st = Get-Content -LiteralPath $statusFile -Raw | ConvertFrom-Json
    if (-not $st.port) { return $null }
    # status 文件可能是上一次运行留下的：进程没了就当它不在
    if ($st.pid) {
      $alive = $null -ne (Get-Process -Id ([int]$st.pid) -ErrorAction SilentlyContinue)
      if (-not $alive) { return $null }
    }
    $tokFile = Join-Path $env:ProgramData 'AliceUIA\token.txt'
    $tok = ''
    if (Test-Path $tokFile) { $tok = (Get-Content -LiteralPath $tokFile -Raw).Trim() }
    return @{ port = [int]$st.port; token = $tok; pid = [int]$st.pid; uiAccess = [int]$st.uiAccessToken }
  } catch { return $null }
}

function Invoke-UiaDaemon($daemon, $fields) {
  $parts = @()
  foreach ($k in $fields.Keys) { $parts += ("{0}={1}" -f $k, $fields[$k]) }
  $line = $parts -join '|'
  $c = New-Object System.Net.Sockets.TcpClient
  try {
    $ar = $c.BeginConnect('127.0.0.1', $daemon.port, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne(1500)) { return $null }
    $c.EndConnect($ar)
    $ns = $c.GetStream()
    $ns.ReadTimeout = 45000
    $b = [Text.Encoding]::UTF8.GetBytes($line + "`n")
    $ns.Write($b, 0, $b.Length); $ns.Flush()
    $rd = New-Object System.IO.StreamReader($ns, [Text.Encoding]::UTF8)
    $resp = $rd.ReadLine()
    if ([string]::IsNullOrEmpty($resp)) { return $null }
    return ($resp | ConvertFrom-Json)
  } catch {
    return $null
  } finally {
    try { $c.Close() } catch { }
  }
}

function Get-ForegroundInfo {
  $h = [CuNative]::GetForegroundWindow()
  $procId = 0
  [void][CuNative]::GetWindowThreadProcessId($h, [ref]$procId)
  $name = ''
  try { $name = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch { }
  return @{ hwnd = [int64]$h; title = [CuNative]::WindowTitle($h); process = $name; pid = $procId }
}

# 安全闸 I1：注入前必须确认前台就是目标窗口。fail-closed：缺声明/读不到/不匹配 一律拒绝。
function Assert-InjectionTarget($flags) {
  if ($flags.allowAny) { return }
  $hasTitle = -not [string]::IsNullOrWhiteSpace($flags.expect)
  $hasHwnd = $null -ne $flags.expectHwnd
  if (-not $hasTitle -and -not $hasHwnd) {
    Fail 'guard' 'INJECTION_REFUSED: 缺少 --expect <标题子串> 或 --expect-hwnd <hwnd>。注入类操作必须声明目标窗口（可在确知风险时用 --allow-any 显式放行）。'
  }
  $fg = Get-ForegroundInfo
  if (-not $fg -or $fg.hwnd -eq 0) { Fail 'guard' 'INJECTION_REFUSED: 读不到前台窗口。' }
  if ($hasHwnd -and [int64]$fg.hwnd -eq [int64]$flags.expectHwnd) { return }
  if ($hasTitle -and $fg.title.ToLowerInvariant().Contains($flags.expect.ToLowerInvariant())) { return }
  Fail 'guard' ("INJECTION_REFUSED: 前台窗口与期望不符。前台 hwnd={0} process={1} title={2} ; 期望 title~{3} hwnd={4}" -f $fg.hwnd, $fg.process, ($fg.title), $flags.expect, $flags.expectHwnd)
}

$cmd = if ($Rest.Count -gt 0) { $Rest[0] } else { 'probe' }
$parsed = Split-Flags ($Rest | Select-Object -Skip 1)
$pos = $parsed.pos
$flags = $parsed.flags

$json = @{ ok = $true; command = $cmd }

try {
  switch ($cmd) {

    'probe' {
      $fg = Get-ForegroundInfo
      $p = New-Object CuNative+POINT
      [void][CuNative]::GetCursorPos([ref]$p)
      $json.metrics = @{
        screenW         = [CuNative]::GetSystemMetrics(0)
        screenH         = [CuNative]::GetSystemMetrics(1)
        virtualW        = [CuNative]::GetSystemMetrics(78)
        virtualH        = [CuNative]::GetSystemMetrics(79)
        monitors        = [CuNative]::GetSystemMetrics(80)
        inputStructSize = [CuNative]::InputStructSize()
        processArch     = [Environment]::Is64BitProcess
        dpiAwareCall    = $script:dpiAware
        coordinateSpace = 'physical'
      }
      $json.cursor = @{ x = $p.X; y = $p.Y; space = 'physical' }
      $json.foreground = $fg
      $json.windowCount = ([CuNative]::AllWindows()).Count
      $json.psVersion = $PSVersionTable.PSVersion.ToString()
    }

    'cursor' {
      $p = New-Object CuNative+POINT
      [void][CuNative]::GetCursorPos([ref]$p)
      $json.cursor = @{ x = $p.X; y = $p.Y; space = 'physical' }
    }

    'move' {
      if ($pos.Count -lt 2) { Fail 'args' 'move <x> <y> [--expect t | --expect-hwnd h | --allow-any]' }
      Assert-InjectionTarget $flags
      $x = [int]$pos[0]; $y = [int]$pos[1]
      $ok = [CuNative]::SetCursorPos($x, $y)
      Start-Sleep -Milliseconds 40
      $p = New-Object CuNative+POINT
      [void][CuNative]::GetCursorPos([ref]$p)
      $json.moved = @{ ok = $ok; requested = @{ x = $x; y = $y }; actual = @{ x = $p.X; y = $p.Y } }
    }

    'click' {
      if ($pos.Count -lt 2) { Fail 'args' 'click <x> <y> [left|right|middle] [single|double] [target flags]' }
      Assert-InjectionTarget $flags
      $x = [int]$pos[0]; $y = [int]$pos[1]
      $button = if ($pos.Count -gt 2) { [string]$pos[2] } else { 'left' }
      $count = if ($pos.Count -gt 3 -and [string]$pos[3] -eq 'double') { 2 } else { 1 }
      # ★ fail-closed（2026-10-26 事故 · 装同花顺期货通时踩到）：
      #   SetCursorPos 的返回值曾被丢弃 ⇒ 光标没移动也照点，点在**光标当时所在处**，
      #   而返回里的 at 填的是**请求值** ⇒ 调用方读到「点成功了」，界面毫无反应。
      #   判据：SetCursorPos 返回 true **且** GetCursorPos 回读落在目标 ±tol 内，两个都成立才点。
      #   ⚠ 已知会锁光标的场景：目标窗口（WPF 模态）处于前台时 SetCursorPos 返回 false。
      $ok = [CuNative]::SetCursorPos($x, $y)
      Start-Sleep -Milliseconds 60
      $p = New-Object CuNative+POINT
      [void][CuNative]::GetCursorPos([ref]$p)
      $tol = 2
      $landed = ([Math]::Abs($p.X - $x) -le $tol) -and ([Math]::Abs($p.Y - $y) -le $tol)
      if ($ok -and $landed) {
        for ($i = 0; $i -lt $count; $i++) {
          [CuNative]::MouseButton($button, $true)
          Start-Sleep -Milliseconds 30
          [CuNative]::MouseButton($button, $false)
          if ($i -lt $count - 1) { Start-Sleep -Milliseconds 90 }
        }
        Start-Sleep -Milliseconds 60
        $after = Get-ForegroundInfo
        $json.clicked = @{ ok = $true; at = @{ x = $x; y = $y }; actual = @{ x = $p.X; y = $p.Y }; button = $button; count = $count; foregroundAfter = $after }
      } else {
        $json.clicked = @{
          ok = $false
          at = @{ x = $x; y = $y }
          actual = @{ x = $p.X; y = $p.Y }
          setCursorPos = $ok
          reason = '光标未到达目标点 ⇒ fail-closed，未执行点击。常见原因：目标窗口在前台时锁住光标；也可能坐标超出屏幕或 DPI 空间不一致'
        }
      }
    }

    'drag' {
      if ($pos.Count -lt 4) { Fail 'args' 'drag <x1> <y1> <x2> <y2> [left|right] [target flags]' }
      Assert-InjectionTarget $flags
      $x1 = [int]$pos[0]; $y1 = [int]$pos[1]; $x2 = [int]$pos[2]; $y2 = [int]$pos[3]
      $button = if ($pos.Count -gt 4) { [string]$pos[4] } else { 'left' }
      # ★ fail-closed（2026-10-26 · 与 click 同一事故同源）：
      #   SetCursorPos 的返回值曾被丢弃 ⇒ **起点没到位就按下左键** ⇒ 在错误位置开始拖
      #   （实测风险：可能拖走窗口、拖坏选中），而返回只报 from/to 请求值 ⇒ 调用方读到"拖过了"。
      #   判据：起点必须 SetCursorPos 返回 true **且** 回读落在 ±tol 内，才允许按下鼠标键。
      #   终点同样验：拖动中途光标可能被锁，终点没到 = 拖拽中断，必须如实报 ok=false。
      $tol = 2
      $okStart = [CuNative]::SetCursorPos($x1, $y1)
      Start-Sleep -Milliseconds 80
      $p = New-Object CuNative+POINT
      [void][CuNative]::GetCursorPos([ref]$p)
      $landedStart = ([Math]::Abs($p.X - $x1) -le $tol) -and ([Math]::Abs($p.Y - $y1) -le $tol)
      if (-not ($okStart -and $landedStart)) {
        $json.dragged = @{
          ok          = $false
          from        = @{ x = $x1; y = $y1 }
          to          = @{ x = $x2; y = $y2 }
          startActual = @{ x = $p.X; y = $p.Y }
          setCursorPos = $okStart
          pulled      = $false
          reason      = '起点光标未到位 ⇒ fail-closed，**未按下鼠标键**（所以没有任何东西被拖动）。常见原因：目标窗口在前台时锁住光标；坐标超出屏幕；DPI 空间不一致'
        }
      } else {
        [CuNative]::MouseButton($button, $true)
        Start-Sleep -Milliseconds 80
        $steps = 12
        for ($i = 1; $i -le $steps; $i++) {
          $mx = [int]($x1 + ($x2 - $x1) * $i / $steps)
          $my = [int]($y1 + ($y2 - $y1) * $i / $steps)
          [void][CuNative]::SetCursorPos($mx, $my)
          Start-Sleep -Milliseconds 18
        }
        Start-Sleep -Milliseconds 60
        $pe = New-Object CuNative+POINT
        [void][CuNative]::GetCursorPos([ref]$pe)
        [CuNative]::MouseButton($button, $false)
        Start-Sleep -Milliseconds 80
        $landedEnd = ([Math]::Abs($pe.X - $x2) -le $tol) -and ([Math]::Abs($pe.Y - $y2) -le $tol)
        $json.dragged = @{
          ok        = $landedEnd
          from      = @{ x = $x1; y = $y1 }
          to        = @{ x = $x2; y = $y2 }
          endActual = @{ x = $pe.X; y = $pe.Y }
          startOk   = $true
          endOk     = $landedEnd
          button    = $button
          reason    = $(if ($landedEnd) { '起点与终点都到位（鼠标键已释放）' } else { '终点未到达 ⇒ 拖拽可能中断；鼠标键已尽力释放，请复核目标状态' })
        }
      }
    }

    'scroll' {
      if ($pos.Count -lt 1) { Fail 'args' 'scroll <delta> [x y] [target flags]' }
      Assert-InjectionTarget $flags
      $delta = [int]$pos[0]
      # ★ fail-closed（2026-10-26）：滚轮作用在**光标所在的窗口**，光标没到位就会滚到**别人窗口**
      #   （比 click 更危险：可能滚了主人正在看的页面）。给了坐标就必须先验到位。
      #   不给坐标是**合法语义**（就滚光标当前位置），但必须把那个位置和命中的窗口报出来。
      $tol = 2
      $p = New-Object CuNative+POINT
      [void][CuNative]::GetCursorPos([ref]$p)
      $wantMove = ($pos.Count -gt 2)
      $at = @{ x = $p.X; y = $p.Y }
      $abort = $false
      if ($wantMove) {
        $wx = [int]$pos[1]; $wy = [int]$pos[2]
        $ok = [CuNative]::SetCursorPos($wx, $wy)
        Start-Sleep -Milliseconds 60
        [void][CuNative]::GetCursorPos([ref]$p)
        $landed = ([Math]::Abs($p.X - $wx) -le $tol) -and ([Math]::Abs($p.Y - $wy) -le $tol)
        if (-not ($ok -and $landed)) {
          $json.scrolled = @{
            ok           = $false
            delta        = $delta
            requested    = @{ x = $wx; y = $wy }
            actual       = @{ x = $p.X; y = $p.Y }
            setCursorPos = $ok
            scrolled     = $false
            reason       = '光标未到达指定点 ⇒ fail-closed，**未发滚轮**（否则会滚到光标当前所在的窗口）。常见原因：目标窗口在前台时锁光标；坐标超屏；DPI 空间不一致'
          }
          $abort = $true
        } else {
          $at = @{ x = $p.X; y = $p.Y }
        }
      }
      if (-not $abort) {
        $pt = New-Object CuNative+POINT
        $pt.X = $at.x; $pt.Y = $at.y
        $hw = [CuNative]::WindowFromPoint($pt)
        [CuNative]::Scroll($delta)
        $json.scrolled = @{
          ok                = $true
          delta             = $delta
          moved             = $wantMove
          at                = $at
          windowUnderCursor = @{ hwnd = [int64]$hw; title = [CuNative]::WindowTitle($hw); cls = [CuNative]::ClassName($hw) }
        }
      }
    }

    'post' {
      # 后台投递（PostMessage）：**窄用途，不是前台的替代品**。
      # 证据（2026-10-26 搜得 + 实测）：cua Issue #1623 —— PostMessage(WM_LBUTTONDOWN/UP) 对
      #   **Chromium 不触发 DOM 输入**（网页坐标点击必须走 SendInput）；对多数 WPF/XAML 同样不可靠。
      #   只有**原生 Win32 控件**（button / edit / 标准 dialog）吃这一套。
      # ⇒ 现代应用/网页请走：UIA 语义动作（desktop_semantic_*，优先）或前台注入（click/type）。
      #
      # ⚠ 本命令**有意不做验靶**（Assert-InjectionTarget）：
      #   它不碰光标、不改前台、不写任何输入队列以外的东西，目标是**显式 hwnd**（不是"光标当前所在"）
      #   ⇒ 没有"注入到主人正在用的窗口"的风险面。这是它唯一的优势，别给它加多余的闸。
      #
      # ⚠ 返回值语义（**不许含糊**）：delivered=消息进了队列；verified **恒为 false**。
      #   本 API 没有任何回执机制 ⇒ 谁能确认"控件响应了"，只有调用方自己（读控件值 / 看落盘副作用）。
      #   拿 delivered=true 当成功上报，就是伪造成功。
      if ($pos.Count -lt 3) { Fail 'args' 'post <hwnd> <x> <y> [left|right|middle|wheel:<delta>] —— x,y 是**屏幕坐标**（内部转客户区）' }
      $hwnd = [IntPtr]([int64]$pos[0])
      $sx = [int]$pos[1]; $sy = [int]$pos[2]
      $mode = if ($pos.Count -gt 3) { [string]$pos[3] } else { 'left' }
      $pt = New-Object CuNative+POINT
      $pt.X = $sx; $pt.Y = $sy
      if (-not [CuNative]::ScreenToClient($hwnd, [ref]$pt)) {
        $json.posted = @{ ok = $false; hwnd = [int64]$hwnd; reason = 'ScreenToClient 失败（hwnd 无效或已销毁）' }
      } else {
        $title = [CuNative]::WindowTitle($hwnd)
        $cls = [CuNative]::ClassName($hwnd)
        $visible = [CuNative]::IsWindowVisible($hwnd)
        if ($mode -like 'wheel:*') {
          $delta = [int]$mode.Substring(6)
          $delivered = [CuNative]::PostWheel($hwnd, $pt.X, $pt.Y, $delta)
          $json.posted = @{
            ok        = $delivered
            mode      = 'wheel'
            hwnd      = [int64]$hwnd
            title     = $title
            cls       = $cls
            visible   = $visible
            screen    = @{ x = $sx; y = $sy }
            client    = @{ x = $pt.X; y = $pt.Y }
            delta     = $delta
            delivered = $delivered
            verified  = $false
            warning   = 'PostWheel 只保证消息进了队列，**不保证目标应用处理了**。请自行读状态验证。对 Chromium/网页无效。'
          }
        } else {
          $delivered = [CuNative]::PostClick($hwnd, $pt.X, $pt.Y, $mode)
          $json.posted = @{
            ok        = $delivered
            mode      = 'click'
            hwnd      = [int64]$hwnd
            title     = $title
            cls       = $cls
            visible   = $visible
            screen    = @{ x = $sx; y = $sy }
            client    = @{ x = $pt.X; y = $pt.Y }
            button    = $mode
            delivered = $delivered
            verified  = $false
            warning   = 'PostClick 只保证消息进了队列，**不保证控件响应**。调用方必须自己验证状态变化；对 Chromium 实测无效。宁可失败也不要伪造成功。'
          }
        }
      }
    }

    'uia' {
      # 后台 UIA 通道（2026-10-26 加）：**不抢前台、不动光标**地读 / 操作 UI 元素。
      # 为什么需要它：nuphus-mcp 的 desktop_semantic_* **要求窗口在前台**（且会改前台），
      #   而这里用 NoActivateGuard（WS_EX_NOACTIVATE）让「动作送进去但窗口不被前台化」。
      # 来源：cua 的 windows-background-input-re-plan.md（标 RESOLVED，e2e 6/6 通过）。
      # ⚠ 适用范围：标准 WPF / UWP / Chromium / 原生控件。**自绘窗口读不到**（element_count=1 那种）。
      # ⚠ 键组合（Ctrl+S 等）**不能**走这条——框架靠 GetKeyState 检测按键，只有系统输入队列（SendInput）会更新它。
      # ⚠ 打不进去时**必须如实失败**，不许降级成前台注入来"装成功"（cua 的 background_unavailable 同理）。
      if ($pos.Count -lt 2) { Fail 'args' 'uia list <hwnd> | uia invoke <hwnd> <name子串> | uia setvalue <hwnd> <name子串> <text> [--limit N]' }
      $sub = [string]$pos[0]
      $hwnd = [IntPtr]([int64]$pos[1])
      # ★ 优先走 UIAccess daemon：它不抢前台。本进程内实现（下面）在 Medium IL 下必抢
      #   前台（实测 stolenWhileGuarded=true，WS_EX_NOACTIVATE 拦不住 UIA 的 Select）。
      #   daemon 不可用时才回退，并用 transport=local 如实标明降级。
      if (-not $flags.local) {
        $dmn = Resolve-UiaDaemon
        if ($dmn) {
          $f = [ordered]@{ token = $dmn.token; sub = $sub; hwnd = [int64]$hwnd }
          if ($pos.Count -gt 2) { $f.name = B64Str ([string]$pos[2]) }
          if ($pos.Count -gt 3) { $f.text = B64Str ([string]$pos[3]) }
          if ($flags.limit) { $f.max = [int]$flags.limit }
          if ($flags.force) { $f.force = 1 }
          $dr = Invoke-UiaDaemon $dmn $f
          if ($null -ne $dr) {
            $dr | Add-Member -NotePropertyName transport -NotePropertyValue 'daemon' -Force
            $dr | Add-Member -NotePropertyName daemonUiAccess -NotePropertyValue $dmn.uiAccess -Force
            $json.uia = $dr
            break
          }
        }
      }
      try {
        Add-Type -AssemblyName UIAutomationClient
        Add-Type -AssemblyName UIAutomationTypes
      } catch { Fail 'uia' "加载 UIAutomation 程序集失败: $($_.Exception.Message)" }
      $AE = [System.Windows.Automation.AutomationElement]
      $TS = [System.Windows.Automation.TreeScope]
      $root = $null
      try { $root = $AE::FromHandle($hwnd) } catch { Fail 'uia' "FromHandle 失败：hwnd=$hwnd ($($_.Exception.Message))" }
      if ($null -eq $root) { Fail 'uia' "FromHandle 返回 null：hwnd=$hwnd 不提供 UIA" }
      $rootName = ''
      try { $rootName = $root.Current.Name } catch { }
      $json.uia = @{ sub = $sub; hwnd = [int64]$hwnd; windowName = $rootName }

      if ($sub -eq 'list') {
        $max = if ($flags.limit) { [int]$flags.limit } else { 60 }
        $all = $root.FindAll($TS::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
        $json.uia.totalElements = $all.Count
        $items = @()
        $scanned = 0
        foreach ($el in $all) {
          $scanned++
          $pats = ''
          $o = $null
          if ($el.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$o)) { $pats += 'invoke '; $o = $null }
          if ($el.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$o)) { $pats += 'value '; $o = $null }
          if ($el.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$o)) { $pats += 'select '; $o = $null }
          if ($el.TryGetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern, [ref]$o)) { $pats += 'expand '; $o = $null }
          if ([string]::IsNullOrWhiteSpace($pats)) { continue }
          $cur = $el.Current
          $r = $cur.BoundingRectangle
          # IsOffscreen 是权威（cua 判据 #3）：元素中心落在窗口矩形内也可能被 ScrollViewer 裁剪
          $isSel = $false
          if ($pats.Contains('select')) {
            $so = $null
            if ($el.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$so)) {
              try { $isSel = [bool]$so.Current.IsSelected } catch { }
            }
          }
          $items += @{
            idx       = $items.Count
            name      = $cur.Name
            type      = ($cur.ControlType.ProgrammaticName -replace '^ControlType\.', '')
            patterns  = $pats.Trim()
            offscreen = $cur.IsOffscreen
            enabled   = $cur.IsEnabled
            selected  = $isSel
            rect      = @{ x = [int]$r.X; y = [int]$r.Y; w = [int]$r.Width; h = [int]$r.Height }
          }
          if ($items.Count -ge $max) { break }
        }
        $json.uia.scanned = $scanned
        $json.uia.operableCount = $items.Count
        $json.uia.truncated = ($items.Count -ge $max)
        $json.uia.items = $items
      }
      elseif ($sub -eq 'invoke' -or $sub -eq 'setvalue' -or $sub -eq 'select') {
        if ($pos.Count -lt 3) { Fail 'args' "uia $sub 需要 <name子串>" }
        $needle = [string]$pos[2]
        $text = if ($sub -eq 'setvalue' -and $pos.Count -gt 3) { [string]$pos[3] } else { '' }
        if ($sub -eq 'setvalue') { $wantPattern = [System.Windows.Automation.ValuePattern]::Pattern }
        elseif ($sub -eq 'select') { $wantPattern = [System.Windows.Automation.SelectionItemPattern]::Pattern }
        else { $wantPattern = [System.Windows.Automation.InvokePattern]::Pattern }
        $all = $root.FindAll($TS::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
        $target = $null; $matchedName = ''; $matchedIdx = -1; $i = -1
        foreach ($el in $all) {
          $i++
          $nm = ''
          try { $nm = $el.Current.Name } catch { continue }
          if ([string]::IsNullOrWhiteSpace($nm)) { continue }
          if (-not $nm.ToLowerInvariant().Contains($needle.ToLowerInvariant())) { continue }
          $o = $null
          if ($el.TryGetCurrentPattern($wantPattern, [ref]$o)) { $target = $el; $matchedName = $nm; $matchedIdx = $i; break }
        }
        if ($null -eq $target) { Fail 'uia' "在 hwnd=$hwnd 里找不到「名字含 $needle」且支持 $sub 的元素" }
        # ★ 2026-10-26 事故驱动：SetValue 是**整体替换**，不是插入。我曾对主人正在编辑的
        #   38KB 文档执行它，内容被换成 15 个字符（证据：记事本恢复存档 27657 → 52 字节）。
        #   ⇒ 默认 fail-closed：目标已有内容且新值更短就拒绝，除非显式 --force。
        if ($sub -eq 'setvalue' -and -not $flags.force) {
          $prevVal = ''
          try {
            $pv = $null
            if ($target.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pv)) {
              $prevVal = [string]$pv.Current.Value
            }
          } catch { }
          if ($null -ne $prevVal -and $prevVal.Length -gt 0 -and $text.Length -lt $prevVal.Length) {
            $winTitle = ''
            try { $winTitle = $rootName } catch { }
            Fail 'uia' ("REFUSED: setvalue 是整体替换。窗口「" + $winTitle + "」的目标元素现有 " + $prevVal.Length + " 字符，新值只有 " + $text.Length + " 字符，**未写入任何内容**。确认要替换请加 --force")
          }
        }
        # ★ 守卫必须在动作**之前**武装：WPF 的 UIElement.Focus()→SetForegroundWindow 发生在动作执行期间
        $fgBefore = [int64][CuNative]::GetForegroundWindow()
        $guard = $null
        $guardArmed = $false
        $fgDuring = -1
        $actErr = ''
        try {
          $guard = New-Object 'CuNative+NoActivateGuard' -ArgumentList $hwnd
          $guardArmed = [bool]$guard.Armed
          $p = $null
          [void]$target.TryGetCurrentPattern($wantPattern, [ref]$p)
          if ($sub -eq 'setvalue') { $p.SetValue($text) }
          elseif ($sub -eq 'select') { $p.Select() }
          else { $p.Invoke() }
          Start-Sleep -Milliseconds 180
          # ★ 守卫**仍然武装时**读一次前台：用来区分「守卫期间就被抢」与「守卫释放后才被抢」
          $fgDuring = [int64][CuNative]::GetForegroundWindow()
        } catch {
          $actErr = $_.Exception.Message
        } finally {
          if ($null -ne $guard) { $guard.Dispose() }
        }
        Start-Sleep -Milliseconds 150
        $fgAfter = [int64][CuNative]::GetForegroundWindow()
        $json.uia.action = $sub
        $json.uia.matched = $matchedName
        $json.uia.matchedIndex = $matchedIdx
        $json.uia.guardArmed = $guardArmed
        $json.uia.foregroundBefore = $fgBefore
        $json.uia.foregroundDuringGuard = $fgDuring
        $json.uia.foregroundAfter = $fgAfter
        $json.uia.foregroundUnchanged = ($fgBefore -eq $fgAfter)
        $json.uia.stolenWhileGuarded = ($fgBefore -ne $fgDuring -and $fgDuring -ne -1)
        $json.uia.ok = [string]::IsNullOrEmpty($actErr)
        if ($actErr) { $json.uia.error = $actErr }
      }
      else { Fail 'args' "未知 uia 子命令: $sub（支持 list / invoke / setvalue）" }
    }

    'type' {
      if ($pos.Count -lt 1) { Fail 'args' 'type <base64-utf8> [target flags]' }
      Assert-InjectionTarget $flags
      $text = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([string]$pos[0]))
      $sent = 0; $bad = 0
      foreach ($ch in $text.ToCharArray()) {
        if ([CuNative]::SendUnicodeChar($ch)) { $sent++ } else { $bad++ }
        Start-Sleep -Milliseconds 6
      }
      $json.typed = @{ chars = $text.Length; sent = $sent; failed = $bad }
    }

    'key' {
      if ($pos.Count -lt 1) { Fail 'args' 'key <combo> [target flags]' }
      Assert-InjectionTarget $flags
      $parts = ([string]$pos[0]).ToLowerInvariant().Split('+')
      $codes = @()
      foreach ($part in $parts) {
        $vk = [CuNative]::Vk($part)
        if ($vk -eq 0) { Fail 'vk' "unknown key name: $part" }
        $codes += $vk
      }
      foreach ($vk in $codes) { [void][CuNative]::SendVk($vk, $false); Start-Sleep -Milliseconds 25 }
      for ($i = $codes.Count - 1; $i -ge 0; $i--) { [void][CuNative]::SendVk($codes[$i], $true); Start-Sleep -Milliseconds 20 }
      $json.key = @{ combo = [string]$pos[0]; vks = $codes }
    }

    'keystate' {
      if ($pos.Count -lt 1) { Fail 'args' 'keystate <name>' }
      $vk = [CuNative]::Vk([string]$pos[0])
      if ($vk -eq 0) { Fail 'vk' "unknown key name: $($pos[0])" }
      $s = [int][CuNative]::GetKeyState($vk)
      $a = [int][CuNative]::GetAsyncKeyState($vk)
      $json.keystate = @{
        name    = [string]$pos[0]
        vk      = $vk
        sync    = ($s -band 0x8000) -ne 0
        async   = ($a -band 0x8000) -ne 0
        toggled = ($s -band 0x0001) -ne 0
      }
    }

    'windows' {
      $filter = if ($pos.Count -gt 0) { [string]$pos[0] } else { $null }
      $limit = if ($flags.limit) { [int]$flags.limit } else { 200 }
      $list = @()
      foreach ($h in ([CuNative]::AllWindows())) {
        $title = [CuNative]::WindowTitle($h)
        if ([string]::IsNullOrWhiteSpace($title)) { continue }
        if ($filter -and ($title -notlike "*$filter*")) { continue }
        $r = New-Object CuNative+RECT
        [void][CuNative]::GetWindowRect($h, [ref]$r)
        $procId = 0
        [void][CuNative]::GetWindowThreadProcessId($h, [ref]$procId)
        $procName = ''
        try { $procName = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch { }
        $list += @{
          hwnd      = [int64]$h
          title     = $title
          cls       = [CuNative]::ClassName($h)
          pid       = $procId
          process   = $procName
          visible   = [CuNative]::IsWindowVisible($h)
          minimized = [CuNative]::IsIconic($h)
          rect      = @{ x = $r.Left; y = $r.Top; w = ($r.Right - $r.Left); h = ($r.Bottom - $r.Top) }
        }
        if ($list.Count -ge $limit) { break }
      }
      $json.count = $list.Count
      $json.windows = $list
    }

    'window-at' {
      if ($pos.Count -lt 2) { Fail 'args' 'window-at <x> <y>' }
      $pt = New-Object CuNative+POINT
      $pt.X = [int]$pos[0]; $pt.Y = [int]$pos[1]
      $h = [CuNative]::WindowFromPoint($pt)
      $procId = 0
      [void][CuNative]::GetWindowThreadProcessId($h, [ref]$procId)
      $procName = ''
      try { $procName = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch { }
      $json.windowAt = @{ x = $pt.X; y = $pt.Y; hwnd = [int64]$h; title = [CuNative]::WindowTitle($h); cls = [CuNative]::ClassName($h); pid = $procId; process = $procName }
    }

    'focus' {
      if ($pos.Count -lt 1) { Fail 'args' 'focus <hwnd|title:子串>' }
      $target = [IntPtr]::Zero
      $spec = [string]$pos[0]
      if ($spec -like 'title:*') {
        $needle = $spec.Substring(6)
        foreach ($h in ([CuNative]::AllWindows())) {
          if ([CuNative]::WindowTitle($h) -like "*$needle*") { $target = $h; break }
        }
        if ($target -eq [IntPtr]::Zero) { Fail 'notfound' "no window title contains: $needle" }
      } else {
        $target = [IntPtr]([int64]$spec)
      }
      $ok = [CuNative]::ForceForeground($target)
      Start-Sleep -Milliseconds 400
      $fg = Get-ForegroundInfo
      $json.focused = @{ requested = [int64]$target; apiOk = $ok; landed = ([int64]$fg.hwnd -eq [int64]$target); foreground = $fg }
    }

    'shot' {
      if ($pos.Count -lt 1) { Fail 'args' 'shot <outPath> [--scale N] [--region x,y,w,h] [--window <hwnd>]' }
      $out = [string]$pos[0]
      $scale = if ($flags.scale) { [double]$flags.scale } else { 1.0 }
      Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
      if ($flags.window) {
        $hwnd = [IntPtr]([int64]$flags.window)
        $r = New-Object CuNative+RECT
        [void][CuNative]::GetWindowRect($hwnd, [ref]$r)
        $w = $r.Right - $r.Left; $h = $r.Bottom - $r.Top
        if ($w -le 0 -or $h -le 0) { Fail 'rect' "window rect invalid: ${w}x${h}" }
        $bmp = New-Object System.Drawing.Bitmap $w, $h
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $hdc = $g.GetHdc()
        [void][CuNative]::PrintWindow($hwnd, $hdc, 2)
        $g.ReleaseHdc($hdc)
        $g.Dispose()
        $src = @{ x = $r.Left; y = $r.Top; w = $w; h = $h; kind = 'window' }
      }
      elseif ($flags.region) {
        $parts = ([string]$flags.region).Split(',')
        if ($parts.Count -lt 4) { Fail 'args' "--region 需要 x,y,w,h（用引号包住）" }
        $src = @{ x = [int]$parts[0]; y = [int]$parts[1]; w = [int]$parts[2]; h = [int]$parts[3]; kind = 'region' }
        $bmp = New-Object System.Drawing.Bitmap $src.w, $src.h
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($src.x, $src.y, 0, 0, (New-Object System.Drawing.Size $src.w, $src.h))
        $g.Dispose()
      }
      else {
        $sw = [CuNative]::GetSystemMetrics(0); $sh = [CuNative]::GetSystemMetrics(1)
        $src = @{ x = 0; y = 0; w = $sw; h = $sh; kind = 'full' }
        $bmp = New-Object System.Drawing.Bitmap $sw, $sh
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen(0, 0, 0, 0, (New-Object System.Drawing.Size $sw, $sh))
        $g.Dispose()
      }
      $final = $bmp
      if ($scale -ne 1.0) {
        $nw = [int][Math]::Max(1, [Math]::Round($bmp.Width * $scale))
        $nh = [int][Math]::Max(1, [Math]::Round($bmp.Height * $scale))
        $final = New-Object System.Drawing.Bitmap $nw, $nh
        $g2 = [System.Drawing.Graphics]::FromImage($final)
        $g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g2.DrawImage($bmp, 0, 0, $nw, $nh)
        $g2.Dispose()
      }
      $dir = Split-Path -Parent $out
      if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
      $final.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
      $json.shot = @{
        path = $out; width = $final.Width; height = $final.Height
        source = $src; scale = $scale; bytes = (Get-Item $out).Length; space = 'physical'
      }
      $final.Dispose(); $bmp.Dispose()
    }

    default { Fail 'unknown' "unknown command: $cmd" }
  }
} catch {
  Fail 'exec' $_.Exception.Message
}

Emit $json
