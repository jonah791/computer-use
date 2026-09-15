/**
 * computer-use（agent-computer-use）：让我自己**看屏幕、自己操作鼠标键盘**，
 * 从而独立走完「开发 → 验证 → 迭代」的闭环，不必再由主人当我的眼睛和手。
 *
 * 三层结构：
 *   src/index.ts  工具面（本文件）：参数校验 → 安全闸 → 调 helper → 归一化输出 + 侧车轨迹
 *   src/pure.ts   纯逻辑：安全闸判定 / 输出解析 / 参数构造（离线单测，见 tests/pure.test.mjs）
 *   helper/*      native 层：CuNative.cs（P/Invoke 声明）+ cu-helper.ps1（命令分发）
 *
 * 本机三条硬约束（实测得出，改代码前先读）：
 *   1. **不落盘 exe**：Defender ASR 规则 01443614-… 禁止运行「全新未签名可执行文件」
 *      （事件 1121 实测拦截我们自己编译的 probe.exe）⇒ native 层只能走 `Add-Type` 内存编译，
 *      helper 必须保持 `.ps1 + .cs` 形态，不要"优化"成 exe。
 *   2. **坐标一律物理像素**：Windows PowerShell 5.1 默认 DPI-unaware（看到 1707×1067 逻辑空间），
 *      helper 加载时调 `SetProcessDPIAware()`，之后 GetCursorPos / SetCursorPos / 截图三者同空间
 *      （实测 665 × 1.5 = 998）。⇒ 点击坐标可直接用截图像素。
 *   3. **注入必须验靶**（不变量 I1）：2026-09-15 事故——测试脚本没找到目标窗口却没停，
 *      39 个字符被注入到主人正在使用的浏览器窗口。闸有两道：静态闸（本文件，判"有没有打算"）
 *      + 原子闸（helper 内，注入前一刻复核前台，防"打算了但前台被换掉"）。
 */
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { spawn, type ChildProcess } from 'node:child_process'
import { appendFileSync, mkdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  buildShotArgs, buildShotPath, decideInjectionGuard, injectionFlagArgs,
  normalizeScale, parseHelperJson, summarizeForTrace, toBase64Utf8,
  type HelperResult, type ShotMode,
} from './pure.ts'

export const name = 'agent-computer-use'
export const inject = ['tools'] as const

export interface Config {
  enabled: boolean
  interpreter: string
  helperPath: string
  shotDir: string
  tracePath: string
  timeoutMs: number
}

export const Config = z.object({
  enabled: z.boolean().default(true),
  /** 本机实测：pwsh 不在 PATH，唯一解释器是 Windows PowerShell 5.1。 */
  interpreter: z.string().default('C:/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe'),
  /** 留空则按插件目录解析 `<pkg>/helper/cu-helper.ps1`。 */
  helperPath: z.string().default(''),
  shotDir: z.string().default('E:/alice/_tmp_review/cu-shots'),
  tracePath: z.string().default('E:/alice/.dsh/computer-use-trace.jsonl'),
  timeoutMs: z.number().default(30000),
})

function errorText(e: unknown): string {
  if (e instanceof Error) return e.message
  return String(e)
}

/** 进程级构建自报（可维护性五问之一「线上跑的是哪个构建」）：`<version>@<模块 mtime ms>`。 */
function buildStamp(): string {
  try {
    const here = fileURLToPath(import.meta.url)
    const pkgPath = join(dirname(here), '..', 'package.json')
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version?: string }
    return String(pkg.version ?? '0.0.0') + '@' + String(Math.trunc(statSync(here).mtimeMs))
  } catch {
    return 'unknown@0'
  }
}

export function apply(ctx: Context, config: Config): void {
  const logger = ctx.logger('agent-computer-use')
  const BUILD = buildStamp()

  /** 侧车轨迹：机制必须自证（一行一阶段，可 tail/grep）。观测绝不反噬主流程。 */
  function trace(entry: Record<string, unknown>): void {
    try {
      const p = String(config.tracePath ?? '').trim()
      if (!p) return
      mkdirSync(dirname(p), { recursive: true })
      appendFileSync(p, JSON.stringify({ atMs: Date.now(), build: BUILD, ...entry }) + '\n', 'utf8')
    } catch { /* 静默：观测失败不得影响业务 */ }
  }

  function helperScript(): string {
    const configured = String(config.helperPath ?? '').trim()
    if (configured) return configured
    return join(dirname(fileURLToPath(import.meta.url)), '..', 'helper', 'cu-helper.ps1')
  }

  function runHelper(args: string[], timeoutMs?: number): Promise<HelperResult> {
    const ms = Number(timeoutMs ?? config.timeoutMs ?? 30000)
    const exe = String(config.interpreter ?? '').trim() || 'powershell.exe'
    const script = helperScript()
    return new Promise<HelperResult>((done) => {
      let settled = false
      const finish = (r: HelperResult): void => { if (!settled) { settled = true; done(r) } }
      let child: ChildProcess
      try {
        child = spawn(exe, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, ...args], {
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe'],
        })
      } catch (e) {
        finish({ ok: false, stage: 'spawn', error: errorText(e), data: {} })
        return
      }
      let out = ''
      let err = ''
      const timer = setTimeout(() => {
        try { child.kill() } catch { /* 可能已退出 */ }
        finish({ ok: false, stage: 'timeout', error: 'helper 超时 ' + String(ms) + 'ms', data: {} })
      }, ms)
      child.stdout?.on('data', (d: Buffer) => { out += d.toString('utf8') })
      child.stderr?.on('data', (d: Buffer) => { err += d.toString('utf8') })
      child.on('error', (e) => { clearTimeout(timer); finish({ ok: false, stage: 'spawn', error: errorText(e), data: {} }) })
      child.on('close', (code) => { clearTimeout(timer); finish(parseHelperJson(out, err, code)) })
    })
  }

  /** 统一出口：调用 + 轨迹。op 名即工具名，args 经摘要（绝不含被输入文本）。 */
  async function call(op: string, args: string[], traceArgs: Record<string, unknown>, timeoutMs?: number): Promise<HelperResult> {
    const startedAtMs = Date.now()
    const r = await runHelper(args, timeoutMs)
    trace({
      op, phase: 'call', argv: args.slice(0, 2).join(' '), args: summarizeForTrace(traceArgs),
      stage: r.ok ? 'done' : String(r.stage ?? 'error'), ok: r.ok,
      error: r.ok ? '' : String(r.error ?? '').slice(0, 300),
      durationMs: Date.now() - startedAtMs,
    })
    return r
  }

  const txt = (v: unknown): string => String(v ?? '')

  // ------------------------------------------------------------------ 工具面

  ctx.tools.register(defineTool({
    name: 'cu_probe',
    description: 'computer-use 环境自检：屏幕尺寸/坐标空间/DPI 声明结果/光标位置/前台窗口/窗口总数。'
      + '任何 cu_* 行为异常时第一个调用它——先确认仪器，再怀疑现象。',
    parameters: {},
    output: {
      schema: {
        properties: {
          ok: { type: 'boolean', required: true },
          build: { type: 'string' }, psVersion: { type: 'string' },
          screenW: { type: 'number' }, screenH: { type: 'number' },
          virtualW: { type: 'number' }, virtualH: { type: 'number' }, monitors: { type: 'number' },
          coordinateSpace: { type: 'string' }, dpiAware: { type: 'boolean' }, inputStructSize: { type: 'number' },
          cursorX: { type: 'number' }, cursorY: { type: 'number' },
          foregroundHwnd: { type: 'number' }, foregroundTitle: { type: 'string' }, foregroundProcess: { type: 'string' },
          windowCount: { type: 'number' }, helperPath: { type: 'string' }, error: { type: 'string' },
        },
        additionalProperties: false, type: 'object',
      },
      render: (_a: unknown, v: any) => [{
        type: 'text',
        text: v.ok
          ? `CU_PROBE ok build=${v.build} ps=${v.psVersion} screen=${v.screenW}x${v.screenH} space=${v.coordinateSpace} dpiAware=${v.dpiAware} inputSize=${v.inputStructSize} cursor=(${v.cursorX},${v.cursorY}) windows=${v.windowCount}\nforeground hwnd=${v.foregroundHwnd} proc=${v.foregroundProcess} title=${JSON.stringify(v.foregroundTitle)}`
          : `CU_ERROR(${v.error})`,
      }],
    },
    async execute() {
      const r = await call('cu_probe', ['probe'], {})
      if (!r.ok) return { ok: false, build: BUILD, helperPath: helperScript(), error: txt(r.error ?? r.stage) }
      const d = r.data
      const m = (d.metrics ?? {}) as Record<string, unknown>
      const c = (d.cursor ?? {}) as Record<string, unknown>
      const f = (d.foreground ?? {}) as Record<string, unknown>
      return {
        ok: true, build: BUILD, helperPath: helperScript(),
        psVersion: txt(d.psVersion), screenW: Number(m.screenW ?? 0), screenH: Number(m.screenH ?? 0),
        virtualW: Number(m.virtualW ?? 0), virtualH: Number(m.virtualH ?? 0), monitors: Number(m.monitors ?? 0),
        coordinateSpace: txt(m.coordinateSpace), dpiAware: m.dpiAwareCall === true,
        inputStructSize: Number(m.inputStructSize ?? 0),
        cursorX: Number(c.x ?? 0), cursorY: Number(c.y ?? 0),
        foregroundHwnd: Number(f.hwnd ?? 0), foregroundTitle: txt(f.title), foregroundProcess: txt(f.process),
        windowCount: Number(d.windowCount ?? 0),
      }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'cu_screen',
    description: '截屏并落盘为 PNG，返回文件路径（用 read_image 亲眼看，或 vision_ask 让 VLM 描述）。'
      + 'mode=full 全屏 / region 指定矩形 / window 指定窗口（PrintWindow，可抓被遮挡窗口）。'
      + '坐标与尺寸一律**物理像素**，与 cu_mouse 的点击坐标同空间，一格不用换算。',
    parameters: {
      mode: { type: 'string', description: 'full(默认) | region | window' },
      x: { type: 'number', description: 'region 的左上角 X' },
      y: { type: 'number', description: 'region 的左上角 Y' },
      w: { type: 'number', description: 'region 宽' },
      h: { type: 'number', description: 'region 高' },
      window: { type: 'number', description: 'mode=window 时的 hwnd（用 cu_windows 拿）' },
      scale: { type: 'number', description: '缩放 0<scale<=1（默认 1；全屏 2560x1600 建议 0.5 省 token）' },
      path: { type: 'string', description: '输出路径（默认自动按时间戳生成到 shotDir）' },
    },
    output: {
      schema: {
        properties: {
          ok: { type: 'boolean', required: true },
          path: { type: 'string' }, width: { type: 'number' }, height: { type: 'number' }, bytes: { type: 'number' },
          mode: { type: 'string' }, sourceX: { type: 'number' }, sourceY: { type: 'number' },
          sourceW: { type: 'number' }, sourceH: { type: 'number' }, space: { type: 'string' }, error: { type: 'string' },
        },
        additionalProperties: false, type: 'object',
      },
      render: (_a: unknown, v: any) => [{
        type: 'text',
        text: v.ok
          ? `CU_SCREEN ${v.path} ${v.width}x${v.height} bytes=${v.bytes} mode=${v.mode} source=(${v.sourceX},${v.sourceY},${v.sourceW},${v.sourceH}) space=${v.space}`
          : `CU_ERROR(${v.error})`,
      }],
    },
    async execute(args: {
      mode?: string
      x?: number; y?: number; w?: number; h?: number
      window?: number; scale?: number; path?: string
    }) {
      const raw = String(args.mode ?? 'full').trim().toLowerCase()
      const mode: ShotMode = raw === 'region' || raw === 'window' ? raw : 'full'
      const scale = normalizeScale(args.scale, 1)
      const outPath = String(args.path ?? '').trim() || buildShotPath(String(config.shotDir ?? ''), mode, Date.now())
      const region = mode === 'region'
        ? { x: Number(args.x ?? 0), y: Number(args.y ?? 0), w: Number(args.w ?? 0), h: Number(args.h ?? 0) }
        : undefined
      let argv: string[]
      try {
        argv = buildShotArgs({ outPath, mode, scale, ...(region ? { region } : {}), ...(mode === 'window' ? { windowHwnd: Number(args.window ?? 0) } : {}) })
      } catch (e) {
        return { ok: false, error: 'CU_ERROR(参数非法: ' + errorText(e) + ')' }
      }
      const r = await call('cu_screen', argv, { mode, scale, hasPath: outPath })
      if (!r.ok) return { ok: false, error: txt(r.error ?? r.stage) }
      const s = (r.data.shot ?? {}) as Record<string, unknown>
      const src = (s.source ?? {}) as Record<string, unknown>
      return {
        ok: true, path: txt(s.path), width: Number(s.width ?? 0), height: Number(s.height ?? 0),
        bytes: Number(s.bytes ?? 0), mode: txt(src.kind), space: txt(s.space),
        sourceX: Number(src.x ?? 0), sourceY: Number(src.y ?? 0), sourceW: Number(src.w ?? 0), sourceH: Number(src.h ?? 0),
      }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'cu_windows',
    description: '窗口清单 / 定点查询"这个坐标上是哪个窗口"。find 是**注入前的常规动作**：'
      + '先确认目标窗口存在与它当前的位置，再决定点哪。每行格式 '
      + 'hwnd=<n> pid=<n> proc=<name> vis=<0|1> min=<0|1> rect=x,y,w,h title=<title>。',
    parameters: {
      filter: { type: 'string', description: '标题子串过滤（不分大小写）' },
      point: { type: 'string', description: '定点查询：x,y（物理像素），返回该点命中的窗口' },
      limit: { type: 'number', description: '返回条数上限（默认 60）' },
    },
    output: {
      schema: {
        properties: {
          ok: { type: 'boolean', required: true },
          count: { type: 'number' }, entries: { type: 'array', items: { type: 'string' } },
          windowAtHwnd: { type: 'number' }, windowAtTitle: { type: 'string' }, windowAtProcess: { type: 'string' },
          error: { type: 'string' },
        },
        additionalProperties: false, type: 'object',
      },
      render: (_a: unknown, v: any) => [{
        type: 'text',
        text: v.ok
          ? (v.windowAtHwnd
            ? `CU_WINDOW_AT hwnd=${v.windowAtHwnd} proc=${v.windowAtProcess} title=${JSON.stringify(v.windowAtTitle)}`
            : `CU_WINDOWS count=${v.count}\n` + (Array.isArray(v.entries) ? v.entries.join('\n') : ''))
          : `CU_ERROR(${v.error})`,
      }],
    },
    async execute(args: { filter?: string; point?: string; limit?: number }) {
      const point = String(args.point ?? '').trim()
      if (point) {
        const parts = point.split(',').map((s) => Number(s.trim()))
        if (parts.length < 2 || !Number.isFinite(parts[0]) || !Number.isFinite(parts[1])) {
          return { ok: false, error: 'CU_ERROR(point 需要 x,y)' }
        }
        const r = await call('cu_windows', ['window-at', String(Math.trunc(parts[0] ?? 0)), String(Math.trunc(parts[1] ?? 0))], { point })
        if (!r.ok) return { ok: false, error: txt(r.error ?? r.stage) }
        const w = (r.data.windowAt ?? {}) as Record<string, unknown>
        return { ok: true, windowAtHwnd: Number(w.hwnd ?? 0), windowAtTitle: txt(w.title), windowAtProcess: txt(w.process) }
      }
      const filter = String(args.filter ?? '').trim()
      const limit = Number.isFinite(Number(args.limit)) && Number(args.limit) > 0 ? Math.trunc(Number(args.limit)) : 60
      const argv = ['windows', ...(filter ? [filter] : []), '--limit', String(limit)]
      const r = await call('cu_windows', argv, { filter, limit })
      if (!r.ok) return { ok: false, error: txt(r.error ?? r.stage) }
      const list = Array.isArray(r.data.windows) ? (r.data.windows as Record<string, unknown>[]) : []
      const entries = list.map((x) => {
        const rect = (x.rect ?? {}) as Record<string, unknown>
        return `hwnd=${txt(x.hwnd)} pid=${txt(x.pid)} proc=${txt(x.process)} vis=${x.visible === true ? 1 : 0} min=${x.minimized === true ? 1 : 0} `
          + `rect=${txt(rect.x)},${txt(rect.y)},${txt(rect.w)},${txt(rect.h)} title=${txt(x.title)}`
      })
      return { ok: true, count: Number(r.data.count ?? entries.length), entries }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'cu_focus',
    description: '把窗口切到前台（SetForegroundWindow）。做**注入前的准备**：把目标窗口激活，'
      + '然后用它的标题或 hwnd 作为 cu_mouse/cu_key 的 expectWindow/expectHwnd。'
      + '注意 Windows 可能拒绝后台进程抢焦点——返回里的 foreground 才是事实（apiOk 只是 API 返回值）。',
    parameters: {
      hwnd: { type: 'number', description: '目标 hwnd' },
      title: { type: 'string', description: '按标题子串找窗口（取第一个命中）' },
    },
    output: {
      schema: {
        properties: {
          ok: { type: 'boolean', required: true },
          requested: { type: 'number' }, apiOk: { type: 'boolean' },
          foregroundHwnd: { type: 'number' }, foregroundTitle: { type: 'string' }, error: { type: 'string' },
        },
        additionalProperties: false, type: 'object',
      },
      render: (_a: unknown, v: any) => [{
        type: 'text',
        text: v.ok
          ? `CU_FOCUS requested=${v.requested} apiOk=${v.apiOk} -> foreground hwnd=${v.foregroundHwnd} title=${JSON.stringify(v.foregroundTitle)}`
          : `CU_ERROR(${v.error})`,
      }],
    },
    async execute(args: { hwnd?: number; title?: string }) {
      const title = String(args.title ?? '').trim()
      const hwnd = Number(args.hwnd ?? 0)
      const spec = title ? 'title:' + title : (Number.isFinite(hwnd) && hwnd > 0 ? String(Math.trunc(hwnd)) : '')
      if (!spec) return { ok: false, error: 'CU_ERROR(需要 hwnd 或 title)' }
      const r = await call('cu_focus', ['focus', spec], { spec })
      if (!r.ok) return { ok: false, error: txt(r.error ?? r.stage) }
      const f = (r.data.focused ?? {}) as Record<string, unknown>
      const fg = (f.foreground ?? {}) as Record<string, unknown>
      return {
        ok: true, requested: Number(f.requested ?? 0), apiOk: f.apiOk === true,
        foregroundHwnd: Number(fg.hwnd ?? 0), foregroundTitle: txt(fg.title),
      }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'cu_mouse',
    description: '鼠标注入：move / click / double / drag / scroll（坐标=物理像素，与 cu_screen 同空间）。'
      + '**注入类工具必须声明目标窗口**：给 expectWindow（标题子串）或 expectHwnd；'
      + '前台与期望不符时会被**拒绝执行**（安全闸，事故驱动：曾把字符注入到主人正在用的窗口）。'
      + '确知风险时才用 allowAnyWindow=true 显式放行。',
    parameters: {
      action: { type: 'string', required: true, description: 'move | click | double | drag | scroll' },
      x: { type: 'number', description: '坐标 X（move/click/double/drag 起点/scroll 的可选落点）' },
      y: { type: 'number', description: '坐标 Y' },
      x2: { type: 'number', description: 'drag 终点 X' },
      y2: { type: 'number', description: 'drag 终点 Y' },
      button: { type: 'string', description: 'left(默认) | right | middle' },
      delta: { type: 'number', description: 'scroll 的滚轮增量（正=上滚，一格=120）' },
      expectWindow: { type: 'string', description: '目标窗口标题子串（注入前验靶）' },
      expectHwnd: { type: 'number', description: '目标窗口 hwnd（注入前验靶）' },
      allowAnyWindow: { type: 'boolean', description: '显式跳过验靶（高风险，慎用）' },
    },
    output: {
      schema: {
        properties: {
          ok: { type: 'boolean', required: true },
          action: { type: 'string' }, detail: { type: 'string' }, error: { type: 'string' },
        },
        additionalProperties: false, type: 'object',
      },
      render: (_a: unknown, v: any) => [{ type: 'text', text: v.ok ? `CU_MOUSE ${v.action}: ${v.detail}` : `CU_ERROR(${v.error})` }],
    },
    async execute(args: {
      action: string
      x?: number; y?: number; x2?: number; y2?: number; button?: string; delta?: number
      expectWindow?: string; expectHwnd?: number; allowAnyWindow?: boolean
    }) {
      const action = String(args.action ?? '').trim().toLowerCase()
      const expect = { ...(args.expectWindow ? { expectWindow: args.expectWindow } : {}), ...(Number.isFinite(Number(args.expectHwnd)) ? { expectHwnd: Number(args.expectHwnd) } : {}), ...(args.allowAnyWindow === true ? { allowAnyWindow: true } : {}) }
      // 静态闸：只判「有没有打算」（不触进程）；no-foreground 表示声明齐备、交 helper 的原子闸复核
      const guard = decideInjectionGuard(expect, null)
      if (!guard.allowed && guard.code !== 'no-foreground') {
        return { ok: false, action, error: 'INJECTION_REFUSED: ' + guard.reason }
      }
      const flags = injectionFlagArgs(expect)
      const button = (String(args.button ?? 'left').trim().toLowerCase() || 'left')
      const xi = Math.trunc(Number(args.x ?? NaN)); const yi = Math.trunc(Number(args.y ?? NaN))
      const x2i = Math.trunc(Number(args.x2 ?? NaN)); const y2i = Math.trunc(Number(args.y2 ?? NaN))
      let argv: string[]
      if (action === 'move') {
        if (!Number.isFinite(xi) || !Number.isFinite(yi)) return { ok: false, action, error: 'CU_ERROR(move 需要 x/y)' }
        argv = ['move', String(xi), String(yi), ...flags]
      } else if (action === 'click' || action === 'double') {
        if (!Number.isFinite(xi) || !Number.isFinite(yi)) return { ok: false, action, error: 'CU_ERROR(click 需要 x/y)' }
        argv = ['click', String(xi), String(yi), button, action === 'double' ? 'double' : 'single', ...flags]
      } else if (action === 'drag') {
        if (![xi, yi, x2i, y2i].every((n) => Number.isFinite(n))) return { ok: false, action, error: 'CU_ERROR(drag 需要 x/y/x2/y2)' }
        argv = ['drag', String(xi), String(yi), String(x2i), String(y2i), button, ...flags]
      } else if (action === 'scroll') {
        const delta = Math.trunc(Number(args.delta ?? -120))
        argv = ['scroll', String(delta)]
        if (Number.isFinite(xi) && Number.isFinite(yi)) argv.push(String(xi), String(yi))
        argv.push(...flags)
      } else {
        return { ok: false, action, error: 'CU_ERROR(未知 action: ' + action + ')' }
      }
      const r = await call('cu_mouse', argv, { action, x: xi, y: yi, x2: x2i, y2: y2i, button, expect: expect })
      if (!r.ok) return { ok: false, action, error: txt(r.error ?? r.stage) }
      const detail = action === 'move'
        ? JSON.stringify(r.data.moved ?? {})
        : action === 'scroll'
          ? JSON.stringify(r.data.scrolled ?? {})
          : action === 'drag'
            ? JSON.stringify(r.data.dragged ?? {})
            : JSON.stringify(r.data.clicked ?? {})
      return { ok: true, action, detail }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'cu_key',
    description: '键盘注入：keys 发组合键（如 "enter" / "ctrl+s" / "win" / "ctrl+shift+esc"），'
      + 'text 发任意 Unicode 文本（中文也可以；内部走 base64 通道，不经命令行转义）。'
      + '**注入类工具必须声明目标窗口**（expectWindow / expectHwnd），不符即拒绝。'
      + 'verifyKey 传键名时，注入后读回该键状态（CapsLock 之类的可证伪判据）——用于自证"真的注入了"。',
    parameters: {
      keys: { type: 'string', description: '组合键，+ 分隔，如 "ctrl+s"' },
      text: { type: 'string', description: '要输入的文本（Unicode，含中文）' },
      expectWindow: { type: 'string', description: '目标窗口标题子串（注入前验靶）' },
      expectHwnd: { type: 'number', description: '目标窗口 hwnd（注入前验靶）' },
      allowAnyWindow: { type: 'boolean', description: '显式跳过验靶（高风险，慎用）' },
      verifyKey: { type: 'string', description: '注入后读回该键状态，如 "capslock"' },
    },
    output: {
      schema: {
        properties: {
          ok: { type: 'boolean', required: true },
          keys: { type: 'string' }, typedChars: { type: 'number' }, sent: { type: 'number' }, failed: { type: 'number' },
          verifyName: { type: 'string' }, verifyToggled: { type: 'boolean' }, verifySync: { type: 'boolean' },
          error: { type: 'string' },
        },
        additionalProperties: false, type: 'object',
      },
      render: (_a: unknown, v: any) => [{
        type: 'text',
        text: v.ok
          ? `CU_KEY${v.keys ? ' keys=' + v.keys : ''}${v.typedChars ? ' typed=' + v.typedChars + ' chars (sent=' + v.sent + ' failed=' + v.failed + ')' : ''}`
            + (v.verifyName ? ` verify[${v.verifyName}] toggled=${v.verifyToggled} sync=${v.verifySync}` : '')
          : `CU_ERROR(${v.error})`,
      }],
    },
    async execute(args: {
      keys?: string; text?: string
      expectWindow?: string; expectHwnd?: number; allowAnyWindow?: boolean; verifyKey?: string
    }) {
      const expect = { ...(args.expectWindow ? { expectWindow: args.expectWindow } : {}), ...(Number.isFinite(Number(args.expectHwnd)) ? { expectHwnd: Number(args.expectHwnd) } : {}), ...(args.allowAnyWindow === true ? { allowAnyWindow: true } : {}) }
      const guard = decideInjectionGuard(expect, null)
      if (!guard.allowed && guard.code !== 'no-foreground') {
        return { ok: false, error: 'INJECTION_REFUSED: ' + guard.reason }
      }
      const keys = String(args.keys ?? '').trim()
      const text = String(args.text ?? '')
      if (!keys && !text) return { ok: false, error: 'CU_ERROR(需要 keys 或 text)' }
      const flags = injectionFlagArgs(expect)
      const out: Record<string, unknown> = { ok: true }
      if (keys) {
        const r = await call('cu_key', ['key', keys, ...flags], { keys, expect })
        if (!r.ok) return { ok: false, keys, error: txt(r.error ?? r.stage) }
        out.keys = keys
      }
      if (text) {
        const r = await call('cu_key', ['type', toBase64Utf8(text), ...flags], { text, expect })
        if (!r.ok) return { ok: false, keys: keys || undefined, error: txt(r.error ?? r.stage) }
        const t = (r.data.typed ?? {}) as Record<string, unknown>
        out.typedChars = Number(t.chars ?? 0); out.sent = Number(t.sent ?? 0); out.failed = Number(t.failed ?? 0)
      }
      const verifyKey = String(args.verifyKey ?? '').trim()
      if (verifyKey) {
        const r = await call('cu_key', ['keystate', verifyKey], { verifyKey }, 10000)
        if (r.ok) {
          const k = (r.data.keystate ?? {}) as Record<string, unknown>
          out.verifyName = verifyKey; out.verifyToggled = k.toggled === true; out.verifySync = k.sync === true
        }
      }
      return out as { ok: boolean; keys?: string; typedChars?: number; sent?: number; failed?: number; verifyName?: string; verifyToggled?: boolean; verifySync?: boolean }
    },
  }))

  logger.info('computer-use ready build=%s helper=%s interpreter=%s', BUILD, helperScript(), String(config.interpreter ?? ''))
  trace({ op: 'apply', phase: 'boot', stage: 'done', ok: true, build: BUILD, helper: helperScript(), interpreter: String(config.interpreter ?? '') })
}
