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
      default { $pos += $a }
    }
  }
  return @{ pos = $pos; flags = $flags }
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
      [void][CuNative]::SetCursorPos($x, $y)
      Start-Sleep -Milliseconds 60
      for ($i = 0; $i -lt $count; $i++) {
        [CuNative]::MouseButton($button, $true)
        Start-Sleep -Milliseconds 30
        [CuNative]::MouseButton($button, $false)
        if ($i -lt $count - 1) { Start-Sleep -Milliseconds 90 }
      }
      Start-Sleep -Milliseconds 60
      $after = Get-ForegroundInfo
      $json.clicked = @{ at = @{ x = $x; y = $y }; button = $button; count = $count; foregroundAfter = $after }
    }

    'drag' {
      if ($pos.Count -lt 4) { Fail 'args' 'drag <x1> <y1> <x2> <y2> [left|right] [target flags]' }
      Assert-InjectionTarget $flags
      $x1 = [int]$pos[0]; $y1 = [int]$pos[1]; $x2 = [int]$pos[2]; $y2 = [int]$pos[3]
      $button = if ($pos.Count -gt 4) { [string]$pos[4] } else { 'left' }
      [void][CuNative]::SetCursorPos($x1, $y1)
      Start-Sleep -Milliseconds 80
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
      [CuNative]::MouseButton($button, $false)
      Start-Sleep -Milliseconds 80
      $json.dragged = @{ from = @{ x = $x1; y = $y1 }; to = @{ x = $x2; y = $y2 }; button = $button }
    }

    'scroll' {
      if ($pos.Count -lt 1) { Fail 'args' 'scroll <delta> [x y] [target flags]' }
      Assert-InjectionTarget $flags
      $delta = [int]$pos[0]
      if ($pos.Count -gt 2) {
        [void][CuNative]::SetCursorPos([int]$pos[1], [int]$pos[2])
        Start-Sleep -Milliseconds 60
      }
      [CuNative]::Scroll($delta)
      $json.scrolled = @{ delta = $delta }
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
      if ([CuNative]::IsIconic($target)) { [void][CuNative]::ShowWindow($target, [CuNative]::SW_RESTORE) }
      else { [void][CuNative]::ShowWindow($target, [CuNative]::SW_SHOW) }
      $ok = [CuNative]::SetForegroundWindow($target)
      Start-Sleep -Milliseconds 400
      $json.focused = @{ requested = [int64]$target; apiOk = $ok; foreground = (Get-ForegroundInfo) }
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
