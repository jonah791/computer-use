/**
 * computer-use 的纯逻辑（零 IO，可离线单测）：注入安全闸、helper 输出解析、参数构造。
 *
 * 这一层存在的理由：把「决策」从 spawn/进程/文件系统里搬出来，
 * 让安全闸与解析逻辑能被**没有桌面环境**的测试直接证伪（见 tests/pure.test.mjs）。
 */

/** 前台窗口形状（helper 的 Get-ForegroundInfo 输出）。 */
export interface ForegroundInfo {
  hwnd: number
  title: string
  process?: string
  pid?: number
}

/** 注入类调用的目标声明。 */
export interface ExpectTarget {
  expectWindow?: string
  expectHwnd?: number
  allowAnyWindow?: boolean
}

export type GuardCode = 'ok' | 'no-expect' | 'no-foreground' | 'mismatch'

export interface GuardDecision {
  allowed: boolean
  code: GuardCode
  reason: string
}

/**
 * 注入安全闸（不变量 I1）。**fail-closed**：缺声明 / 读不到前台 / 与期望不符 → 一律拒绝。
 *
 * 事故来源（2026-09-15）：测试脚本的目标窗口查找失败后**没有停下**，
 * 39 个字符被注入到当时的前台窗口（主人正在使用的浏览器），并落在了对话输入框里。
 * ⇒ 结论：注入类操作**必须验靶**，且「找不到目标」必须是硬停，绝不能退回「谁在前台就发给谁」。
 *
 * 本函数是**静态闸**（不触进程，只判声明是否成立）；helper 内另有一道**原子闸**（注入前一刻复核前台），
 * 二者互补：静态闸拦「没打算」，原子闸拦「打算了但前台被换掉」。
 */
export function decideInjectionGuard(expect: ExpectTarget, foreground: ForegroundInfo | null): GuardDecision {
  if (expect.allowAnyWindow === true) {
    return { allowed: true, code: 'ok', reason: 'allowAnyWindow=true：已显式放行（高风险路径，仅在确知目标时使用）' }
  }
  const title = typeof expect.expectWindow === 'string' ? expect.expectWindow.trim() : ''
  const hwnd = typeof expect.expectHwnd === 'number' && Number.isFinite(expect.expectHwnd) ? expect.expectHwnd : undefined
  if (!title && hwnd === undefined) {
    return {
      allowed: false,
      code: 'no-expect',
      reason: '缺少 expectWindow/expectHwnd：注入类操作必须声明目标窗口（确知风险时可显式设 allowAnyWindow=true）',
    }
  }
  if (!foreground) {
    return { allowed: false, code: 'no-foreground', reason: '读不到前台窗口：拒绝注入' }
  }
  if (hwnd !== undefined && Number(foreground.hwnd) === Number(hwnd)) {
    return { allowed: true, code: 'ok', reason: 'hwnd 匹配：' + String(hwnd) }
  }
  if (title && String(foreground.title ?? '').toLowerCase().includes(title.toLowerCase())) {
    return { allowed: true, code: 'ok', reason: '标题匹配：' + title }
  }
  return {
    allowed: false,
    code: 'mismatch',
    reason:
      '目标不匹配：前台 hwnd=' + String(foreground.hwnd) +
      ' title=' + JSON.stringify(String(foreground.title ?? '')) +
      ' 期望 ' + (title ? 'title~' + title : '') + (hwnd !== undefined ? ' hwnd=' + String(hwnd) : ''),
  }
}

/** 把目标声明翻译成 helper 的命令行旗标。 */
export function injectionFlagArgs(expect: ExpectTarget): string[] {
  const args: string[] = []
  if (expect.allowAnyWindow === true) {
    args.push('--allow-any')
    return args
  }
  const title = typeof expect.expectWindow === 'string' ? expect.expectWindow.trim() : ''
  if (title) args.push('--expect', title)
  if (typeof expect.expectHwnd === 'number' && Number.isFinite(expect.expectHwnd)) {
    args.push('--expect-hwnd', String(Math.trunc(expect.expectHwnd)))
  }
  return args
}

export interface HelperResult {
  ok: boolean
  stage?: string
  error?: string
  data: Record<string, unknown>
}

/**
 * 解析 helper 的 stdout。取最后一行非空输出（helper 只 emit 一行 JSON）；
 * 无输出 / 非 JSON / exit≠0 都要给出**可诊断**的失败原因（stderr 摘要入错误信息）。
 */
export function parseHelperJson(stdout: string, stderr: string, exitCode: number | null): HelperResult {
  const lines = String(stdout ?? '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean)
  const line = lines.length > 0 ? String(lines[lines.length - 1]) : ''
  if (!line) {
    const errTail = String(stderr ?? '').trim().slice(-300)
    return {
      ok: false,
      stage: 'empty-stdout',
      error: 'helper 无输出（exit=' + String(exitCode) + '）' + (errTail ? ' / stderr: ' + errTail : ''),
      data: {},
    }
  }
  try {
    const parsed: unknown = JSON.parse(line)
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false, stage: 'bad-json', error: 'helper 输出不是对象: ' + line.slice(0, 200), data: {} }
    }
    const obj = parsed as Record<string, unknown>
    const ok = obj.ok === true
    const stage = typeof obj.stage === 'string' ? obj.stage : undefined
    const error = typeof obj.error === 'string' ? obj.error : undefined
    return { ok, ...(stage ? { stage } : {}), ...(error ? { error } : {}), data: obj }
  } catch {
    return { ok: false, stage: 'bad-json', error: 'helper 输出非 JSON: ' + line.slice(0, 200), data: {} }
  }
}

/** 文本 → base64(UTF-8)：命令行不传原始文本，避免编码与转义丢失。 */
export function toBase64Utf8(text: string): string {
  return Buffer.from(String(text ?? ''), 'utf8').toString('base64')
}

/** 截图缩放系数：非法值回落；上限 1（放大没有意义）。 */
export function normalizeScale(value: unknown, fallback = 1): number {
  const n = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(n) || n <= 0) return fallback
  return n > 1 ? 1 : n
}

export type ShotMode = 'full' | 'region' | 'window'

export interface ShotSpec {
  outPath: string
  mode: ShotMode
  scale?: number
  region?: { x: number; y: number; w: number; h: number }
  windowHwnd?: number
}

/**
 * 构造 shot 命令的参数数组。
 * `--region` 的值必须是**单个** argv 元素 `x,y,w,h`（命令行走 spawn 数组，不经 shell，无需引号）。
 * 2026-09-15 实测坑：在 PowerShell 里手输 `300,1150,2200,320` 会被解析成数组并压成空格分隔串 ⇒ 帮助器报 Int32 转换失败。
 */
export function buildShotArgs(spec: ShotSpec): string[] {
  const args = ['shot', spec.outPath]
  const scale = normalizeScale(spec.scale, 1)
  if (scale !== 1) args.push('--scale', String(scale))
  if (spec.mode === 'window') {
    const hwnd = typeof spec.windowHwnd === 'number' && Number.isFinite(spec.windowHwnd) ? Math.trunc(spec.windowHwnd) : 0
    if (hwnd <= 0) throw new Error('mode=window 需要合法的 window(hwnd)')
    args.push('--window', String(hwnd))
  } else if (spec.mode === 'region') {
    const r = spec.region
    if (!r) throw new Error('mode=region 需要 x/y/w/h')
    for (const k of ['x', 'y', 'w', 'h'] as const) {
      if (!Number.isFinite(r[k]) || r[k] <= 0) throw new Error('region.' + k + ' 非法: ' + String(r[k]))
    }
    args.push('--region', [Math.trunc(r.x), Math.trunc(r.y), Math.trunc(r.w), Math.trunc(r.h)].join(','))
  }
  return args
}

/** 截图落盘路径：未指定时按时间戳生成，避免并发/连续调用互相覆盖。 */
export function buildShotPath(dir: string, mode: ShotMode, ts: number): string {
  const d = String(dir ?? '').trim().replace(/[\\/]+$/, '')
  const stamp = new Date(ts).toISOString().replace(/[:.]/g, '-')
  return d + '/cu-' + mode + '-' + stamp + '.png'
}

/** 参数摘要（仅形状，**绝不记录被输入的文本**——隐私纪律）。 */
export function summarizeForTrace(args: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(args ?? {})) {
    if (k === 'text') out.textChars = typeof v === 'string' ? v.length : 0
    else if (typeof v === 'string') out[k] = v.length > 80 ? v.slice(0, 80) + '…' : v
    else out[k] = v
  }
  return out
}
