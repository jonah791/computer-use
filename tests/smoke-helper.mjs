/**
 * 端到端冒烟（**本机专用**，需要桌面）：不经过 DSH，直接按插件的调用方式跑 helper。
 * 不匹配 `tests/*.test.mjs` 通配，因此不会进 CI 的常规单测；用法：`node tests/smoke-helper.mjs`
 *
 * 覆盖三类证据：
 *   1. 能力：probe / shot 落盘
 *   2. 安全闸尸体测试（不变量 I1）：无声明必须被拒、错靶必须被拒、正靶放行
 *   3. 注入闭环：显式放行时真的生效（CapsLock 状态翻转）且能复位
 */
import { spawn } from 'node:child_process'
import { existsSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const helper = join(here, '..', 'helper', 'cu-helper.ps1')
const EXE = 'C:/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe'
const SHOT = 'E:/alice/_tmp_review/cu-shots/smoke.png'

function run(args) {
  return new Promise((resolve) => {
    const c = spawn(EXE, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helper, ...args], {
      windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    })
    let out = '', err = ''
    c.stdout.on('data', (d) => { out += d.toString('utf8') })
    c.stderr.on('data', (d) => { err += d.toString('utf8') })
    c.on('error', (e) => resolve({ code: -1, parsed: null, out, err: String(e) }))
    c.on('close', (code) => {
      const lines = out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean)
      let parsed = null
      try { parsed = JSON.parse(lines[lines.length - 1] ?? '') } catch { /* 非 JSON 时 parsed 留 null */ }
      resolve({ code, parsed, out, err })
    })
  })
}

let failed = 0
const check = (name, cond, extra = '') => {
  if (!cond) failed++
  console.log((cond ? 'PASS  ' : 'FAIL  ') + name + (extra ? '   ' + extra : ''))
}

// 1) 能力：probe
const p = await run(['probe'])
check('probe ok', p.parsed?.ok === true)
check('坐标空间 = physical', p.parsed?.metrics?.coordinateSpace === 'physical')
check('DPI-aware 已生效', p.parsed?.metrics?.dpiAwareCall === true)
check('INPUT 结构体尺寸 = 40 (x64)', p.parsed?.metrics?.inputStructSize === 40)
const fgTitle = String(p.parsed?.foreground?.title ?? '')
console.log('      前台窗口 = ' + JSON.stringify(fgTitle))

// 2) 能力：shot 落盘且非空
const s = await run(['shot', SHOT, '--scale', '0.25'])
check('shot ok', s.parsed?.ok === true)
check('shot 落盘非空', existsSync(SHOT) && statSync(SHOT).size > 1000,
  existsSync(SHOT) ? String(statSync(SHOT).size) + ' bytes' : 'missing')

// 3) 尸体测试：无声明注入 → 必须被拒
const noDecl = await run(['key', 'capslock'])
check('无声明注入被拒', noDecl.parsed?.ok === false && String(noDecl.parsed?.error ?? '').includes('INJECTION_REFUSED'),
  'stage=' + String(noDecl.parsed?.stage))

// 4) 尸体测试：错靶（标题不存在）→ 必须被拒
const wrong = await run(['key', 'shift', '--expect', '绝不存在的窗口标题_ZZZ'])
check('错靶注入被拒', wrong.parsed?.ok === false && String(wrong.parsed?.error ?? '').includes('INJECTION_REFUSED'))

// 5) 正靶放行：用当前前台标题作 expect，发一个无副作用的 shift
if (fgTitle) {
  const good = await run(['key', 'shift', '--expect', fgTitle.slice(0, 12)])
  check('正靶放行（shift 无副作用）', good.parsed?.ok === true, String(good.parsed?.error ?? ''))
} else {
  check('正靶放行（shift 无副作用）', false, '拿不到前台标题，跳过不算通过')
}

// 6) 注入闭环：显式放行 → CapsLock 翻转 → 复位
const before = await run(['keystate', 'capslock'])
await run(['key', 'capslock', '--allow-any'])
const mid = await run(['keystate', 'capslock'])
await run(['key', 'capslock', '--allow-any'])
const after = await run(['keystate', 'capslock'])
const b = before.parsed?.keystate?.toggled, m = mid.parsed?.keystate?.toggled, a = after.parsed?.keystate?.toggled
check('注入真的生效（CapsLock 翻转）', b !== m, `before=${b} mid=${m}`)
check('注入后可复位', a === b, `after=${a}`)

console.log('\n' + (failed === 0 ? 'SMOKE_ALL_PASS' : 'SMOKE_FAILED=' + String(failed)))
process.exit(failed === 0 ? 0 : 1)
