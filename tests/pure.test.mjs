/**
 * pure.ts 的离线单测：安全闸 / 输出解析 / 参数构造。
 * 这些用例**不需要桌面环境**，跑在 CI 或任何机器上都成立。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  buildShotArgs, buildShotPath, decideInjectionGuard, injectionFlagArgs,
  normalizeScale, parseHelperJson, summarizeForTrace, toBase64Utf8,
} from '../lib/pure.js'

const FG = { hwnd: 788926, title: 'DSH实例间通讯插件开发 — DSH 本地构建 - Chromium', process: 'chrome' }

test('安全闸：没声明目标 → 拒绝（事故根因）', () => {
  const d = decideInjectionGuard({}, FG)
  assert.equal(d.allowed, false)
  assert.equal(d.code, 'no-expect')
})

test('安全闸：声明了但前台不符 → 拒绝，且理由里带实际上前台', () => {
  const d = decideInjectionGuard({ expectWindow: '记事本' }, FG)
  assert.equal(d.allowed, false)
  assert.equal(d.code, 'mismatch')
  assert.match(d.reason, /788926/)
  assert.match(d.reason, /Chromium/)
})

test('安全闸：标题子串匹配（不分大小写）→ 放行', () => {
  assert.equal(decideInjectionGuard({ expectWindow: 'chromium' }, FG).allowed, true)
  assert.equal(decideInjectionGuard({ expectWindow: 'DSH本地构建'.replace('DSH本地构建', '本地构建') }, FG).allowed, true)
})

test('安全闸：hwnd 匹配 → 放行；不等 → 拒绝', () => {
  assert.equal(decideInjectionGuard({ expectHwnd: 788926 }, FG).allowed, true)
  assert.equal(decideInjectionGuard({ expectHwnd: 123 }, FG).allowed, false)
})

test('安全闸：allowAnyWindow 显式放行（高风险旁路必须显式）', () => {
  const d = decideInjectionGuard({ allowAnyWindow: true }, FG)
  assert.equal(d.allowed, true)
  assert.equal(d.code, 'ok')
})

test('安全闸：读不到前台时，已声明目标 → code=no-foreground（交 helper 原子闸复核）', () => {
  const d = decideInjectionGuard({ expectWindow: 'x' }, null)
  assert.equal(d.allowed, false)
  assert.equal(d.code, 'no-foreground')
})

test('旗标构造：标题 + hwnd 都转成 helper 参数', () => {
  assert.deepEqual(injectionFlagArgs({ expectWindow: 'Notepad', expectHwnd: 42 }), ['--expect', 'Notepad', '--expect-hwnd', '42'])
  assert.deepEqual(injectionFlagArgs({ allowAnyWindow: true, expectWindow: 'ignored' }), ['--allow-any'])
  assert.deepEqual(injectionFlagArgs({}), [])
})

test('输出解析：正常 JSON / 失败 JSON / 空输出 / 非 JSON', () => {
  const ok = parseHelperJson('{"ok":true,"cursor":{"x":1}}', '', 0)
  assert.equal(ok.ok, true)
  assert.deepEqual(ok.data.cursor, { x: 1 })

  const bad = parseHelperJson('{"ok":false,"stage":"guard","error":"INJECTION_REFUSED"}', '', 1)
  assert.equal(bad.ok, false)
  assert.equal(bad.stage, 'guard')
  assert.equal(bad.error, 'INJECTION_REFUSED')

  const empty = parseHelperJson('', 'boom', 1)
  assert.equal(empty.ok, false)
  assert.equal(empty.stage, 'empty-stdout')
  assert.match(empty.error, /boom/)

  const notJson = parseHelperJson('  不是 JSON\n', '', 0)
  assert.equal(notJson.ok, false)
  assert.equal(notJson.stage, 'bad-json')
})

test('输出解析：取最后一行（helper 可能夹带警告）', () => {
  const r = parseHelperJson('warning: x\n{"ok":true,"command":"cursor"}', '', 0)
  assert.equal(r.ok, true)
  assert.equal(r.data.command, 'cursor')
})

test('截图参数：full / region / window / 缩放夹紧', () => {
  assert.deepEqual(buildShotArgs({ outPath: 'a.png', mode: 'full' }), ['shot', 'a.png'])
  assert.deepEqual(
    buildShotArgs({ outPath: 'a.png', mode: 'region', region: { x: 1, y: 2, w: 3, h: 4 }, scale: 0.5 }),
    ['shot', 'a.png', '--scale', '0.5', '--region', '1,2,3,4'],
  )
  assert.deepEqual(
    buildShotArgs({ outPath: 'a.png', mode: 'window', windowHwnd: 99 }),
    ['shot', 'a.png', '--window', '99'],
  )
  // scale > 1 被夹到 1 ⇒ 不出现 --scale
  assert.deepEqual(buildShotArgs({ outPath: 'a.png', mode: 'full', scale: 3 }), ['shot', 'a.png'])
  assert.throws(() => buildShotArgs({ outPath: 'a.png', mode: 'window' }), /hwnd/)
  assert.throws(() => buildShotArgs({ outPath: 'a.png', mode: 'region', region: { x: 0, y: 0, w: 0, h: 5 } }), /region/)
})

test('缩放规整：非法回落、超 1 夹紧', () => {
  assert.equal(normalizeScale(0.5), 0.5)
  assert.equal(normalizeScale(2), 1)
  assert.equal(normalizeScale('abc', 0.75), 0.75)
  assert.equal(normalizeScale(-1, 0.5), 0.5)
})

test('截图路径：带时间戳，不覆盖', () => {
  const p1 = buildShotPath('E:/x/', 'full', 0)
  const p2 = buildShotPath('E:/x', 'full', 60000)
  assert.match(p1, /^E:\/x\/cu-full-.*\.png$/)
  assert.notEqual(p1, p2)
})

test('文本编码：UTF-8 → base64（中文不走命令行转义）', () => {
  assert.equal(toBase64Utf8('abc'), 'YWJj')
  assert.equal(Buffer.from(toBase64Utf8('中文'), 'base64').toString('utf8'), '中文')
})

test('轨迹摘要：只记文本长度，绝不记文本内容（隐私）', () => {
  const s = summarizeForTrace({ keys: 'ctrl+s', text: 'secret-message', x: 10 })
  assert.equal(s.textChars, 14)
  assert.equal(s.keys, 'ctrl+s')
  assert.equal(s.x, 10)
  assert.equal(Object.prototype.hasOwnProperty.call(s, 'text'), false)
  assert.equal(JSON.stringify(s).includes('secret-message'), false)
})
