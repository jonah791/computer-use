# computer-use 语义文档

## 1. 元信息

| 项 | 值 |
|---|---|
| 包名 | `computer-use`（`self-plugins/computer-use`，插件内名 `agent-computer-use`） |
| 版本 | v0.1.0 |
| 状态 | 已实现（本机实测通过） |
| 主副本 | `self-plugins/computer-use/docs/semantic.md`（本文件） |
| 最近复核 | 2026-09-15 |

## 2. 定位与反定位

**定位**：让主脑（爱丽丝）**自己看屏幕、自己操作鼠标键盘**，从而独立走完「开发 → 验证 → 迭代」闭环，
不必再由主人充当眼睛和手。它把「GUI 世界的感知与行动」变成 DSH 工具面的一部分。

**反定位**：
- 不是远程桌面/无人值守自动化框架——没有守护进程、没有任务队列、没有回放；
- 不是无障碍/自动化测试框架（不提供断言与录制），它是**原语层**；
- 不替代 `dsh-agent-browser`（浏览器 CDP 通道）与 `dsh-agent-vision`（VLM 读图）——
  前者对 WebView2/Chromium 能读到 DOM（更精确），本插件是**任意窗口的通用通道**；
  后者省上下文但精度低，本插件返回截图路径供 `read_image` 亲眼看。

**选择原则**：要精确读 Web 内容 → `dsh-agent-browser`；要跨应用/原生窗口 → 本插件。

## 3. 术语

| 术语 | 含义 |
|---|---|
| 物理像素 | 显示器的真实像素（本机 2560×1600）。本插件**一切坐标、尺寸、矩形都用物理像素** |
| 逻辑像素 | 应用在 DPI 缩放下的坐标空间（本机 150% 缩放 ⇒ 1707×1067）。**本插件不使用** |
| helper | `helper/cu-helper.ps1` + `helper/CuNative.cs`，每次调用起一个独立进程，无状态 |
| 靶（target） | 注入类操作声明并将在注入前校验的前台窗口 |
| 验靶 | 注入前确认前台窗口就是靶；不符即拒绝（不变量 I1） |

## 4. 概念模型与不变量

```
工具面 (src/index.ts)   参数校验 → 静态闸 → spawn helper → 归一化输出 + 侧车轨迹
   ↓
纯逻辑 (src/pure.ts)    安全闸判定 / 输出解析 / 参数构造（离线可测）
   ↓
native 层 (helper/*)    P/Invoke：截屏 · 窗口 · 光标 · SendInput/keybd_event + 原子闸
```

**不变量**（违反即缺陷，每条都有对应测试）：

| 编号 | 不变量 | 依据 / 测试 |
|---|---|---|
| **I1** | 注入类操作（move/click/drag/scroll/key/type）**必须验靶**：无声明拒绝、不符拒绝；`allowAnyWindow` 是唯一且必须显式的旁路 | 事故 2026-09-15（见 §9）；`decideInjectionGuard` 6 例 + 冒烟尸体测试 3 例 |
| **I2** | 坐标一律**物理像素**：helper 加载时 `SetProcessDPIAware()`，之后光标读/写与截图同空间 | 同进程前后对比实测 1707×1067 → 2560×1600，665×1.5=998 |
| **I3** | **不落盘可执行文件**：native 层走 `Add-Type` 内存编译 | 本机 Defender ASR `01443614-…` 实测拦截新编译 exe（事件 1121） |
| **I4** | 每次调用**独立进程、无状态**；不驻留、不共享句柄 | 设计选择（528ms/次实测，可接受） |
| **I5** | 轨迹**绝不记录被注入的文本内容**，只记长度 | `summarizeForTrace` 单测 |
| **I6** | 观测（轨迹落盘）失败**不得影响业务** | `trace()` 内 try/catch 吞错 |

## 5. 契约

### 5.1 工具面（6 个）

| 工具 | 作用 | 注入类？ |
|---|---|---|
| `cu_probe` | 环境自检：屏幕/坐标空间/DPI 声明/光标/前台窗口/窗口总数 | 否 |
| `cu_screen` | 截屏落盘（full / region / window，可缩放），返回路径交给 `read_image` | 否 |
| `cu_windows` | 窗口清单（标题/进程/位置/可见）或定点查询「这个坐标上是哪个窗口」 | 否 |
| `cu_focus` | 把窗口切到前台 | 否（但会改变焦点） |
| `cu_mouse` | move / click / double / drag / scroll | **是** |
| `cu_key` | 组合键（`ctrl+s`）与 Unicode 文本；可 `verifyKey` 读回状态自证 | **是** |

### 5.2 调用点清单

| 调用点 | 路径 | 说明 |
|---|---|---|
| 工具注册 | `src/index.ts` `apply()` | 6 个 `ctx.tools.register(defineTool(...))` |
| 纯逻辑引用 | `src/index.ts` ← `src/pure.ts` | 安全闸、参数构造、输出解析、轨迹摘要 |
| 进程调用 | `src/index.ts` `runHelper()` | `spawn(interpreter, ['-File', helper, ...args])`，管道 stdio |
| native 加载 | `helper/cu-helper.ps1` | `Add-Type -TypeDefinition (Get-Content CuNative.cs)` |
| 轨迹落盘 | `config.tracePath`（默认 `E:/alice/.dsh/computer-use-trace.jsonl`） | 一行一阶段 |
| 截图输出 | `config.shotDir`（默认 `E:/alice/_tmp_review/cu-shots`） | 供 `read_image` 消费 |
| 单测 | `tests/pure.test.mjs`（14 例） | 无需桌面 |
| 冒烟 | `tests/smoke-helper.mjs` | **本机专用**（需桌面），不匹配 CI 通配 |

### 5.3 配置项

`interpreter`（默认 Windows PowerShell 5.1 全路径；本机 `pwsh` 不在 PATH）·
`helperPath`（默认按插件目录解析）· `shotDir` · `tracePath` · `timeoutMs`（默认 30000）。

## 6. 边界与信任

- **能力 ≠ 沙箱**：本插件赋予的是**真实鼠标键盘注入能力**，与宿主同权限。它不是安全边界。
- **验靶只是防误伤，不是安全机制**：`allowAnyWindow=true` 可绕过；真正的约束是使用纪律。
- **不保证目标应用响应**：注入成功 ≠ 目标应用接受（可能有模态框、焦点抢占、UAC 隔离）。
  Windows 会阻止后台进程抢焦点 ⇒ `cu_focus` 的 `apiOk` 只是 API 返回值，**以返回的 `foreground` 为准**。
- **UAC 提权窗口**：无法向其注入（系统设计），此时只能请主人操作。

## 7. 可证伪验收

| 编号 | 判据（可被一次测量判真假） | 状态 |
|---|---|---|
| A1 | `cu_probe` 返回 `coordinateSpace=physical`、`dpiAware=true`、`inputStructSize=40` | 已实测 |
| A2 | `cu_screen` 全屏截图落盘且字节数 > 1000（实测 105,161 bytes @0.25 缩放） | 已实测 |
| A3 | 无声明注入返回 `INJECTION_REFUSED`（helper `stage=guard`，exit≠0） | 已实测 |
| A4 | 错靶注入（`--expect` 指向不存在的标题）返回 `INJECTION_REFUSED` | 已实测 |
| A5 | 正靶注入（`--expect` 取当前前台标题前 12 字）被放行 | 已实测 |
| A6 | 显式放行注入 CapsLock 后，`keystate` 的 `toggled` 翻转；再注入一次复位 | 已实测（false→true→false） |
| A7 | 单元测试 14 例全绿（含隐私：轨迹不含文本内容） | 已实测 |
| A8 | helper 每次调用独立进程、无残留（调用后无新增常驻进程） | 已实测 |
| A9 | 在 DSH 会话内 6 个工具全部可见且可调用 | 待线上验收 |
| A10 | 端到端闭环：截屏 → `read_image` 看图 → 按图操作 → 复查截图确认变化 | 待线上验收 |

## 8. 与实现的关系

- 文档描述「是什么/不变量/契约」，实现必须逼近它；**实现变化必须同步本文**（I3 纪律）。
- `src/pure.ts` 是文档第 4 节不变量的**可执行副本**（单测即验收）；`helper/` 是 native 语义的唯一落点。
- 版本史：v0.1.0 首版（probe/screen/windows/focus/mouse/key）。
- **2026-09-22 复核（消除 D3）**：本仓已纳入 DSH Community Fabric 契约面（`dsh-plugin.json` + `src/fabric.ts`）——它属**结构性声明**，不改变上文任何行为语义。此前报「实现比文档新」正是由 `chore(fabric)` 提交推进的 `src/fabric.ts` mtime 触发，而非能力变更。

## 9. 实践修订记录

| 日期 | 触发 | 修订 |
|---|---|---|
| 2026-09-15 | **注入事故**：测试脚本查找目标窗口失败后未硬停，39 个字符被注入到主人正在使用的浏览器窗口（落在对话输入框）。根因是"fail-open"——没找到目标就退回"谁在前台发给谁" | 立 **I1 验靶**：安全闸做两层（TS 静态闸判"有没有打算"+ helper 原子闸在注入前一刻复核前台）；冒烟测试补 3 条尸体测试（无声明/错靶/正靶） |
| 2026-09-15 | Defender **ASR 事件 1121** 实测拦截我们新编译的 `probe.exe`（规则 `01443614-…`） | 立 **I3 不落盘 exe**；native 层改 `Add-Type` 内存编译 |
| 2026-09-15 | PowerShell 5.1 默认 DPI-unaware，坐标空间差 1.5 倍（实测 665 ↔ 998） | 立 **I2 物理像素**；helper 加载即 `SetProcessDPIAware()` 并把 `coordinateSpace` 写进所有返回值 |
| 2026-09-15 | `GetCursorPos` 的 P/Invoke 误写为 `out int x, out int y`（应为 `LPPOINT` 结构）⇒ Y 恒为 0 | 改用 `POINT` 结构体；**声明必须实测**（`inputStructSize` 写进 probe 作为自证） |

## 10. 未决问题

| 编号 | 问题 | 影响 | 处置 |
|---|---|---|---|
| U1 | 常驻 helper（stdin/stdout 服务）可把 528ms 降到 <30ms，是否需要？ | 迭代速度 | 暂不做——528ms 对"看-想-动"循环足够，且常驻进程带来保活与句柄泄漏面 |
| U2 | 是否需要 OCR/UI Automation 通道读控件树（比视觉识别可靠）？ | 复杂界面操作精度 | 待出现"截图像素定位不可靠"的实际场景再评估 |
| U3 | 多显示器：`virtualW/H` 与显示器枚举已返回，但未做跨屏坐标变换验证 | 扩展坞场景 | 本机单显示器，无现场可验；保持观察 |
| U4 | 拖拽的中间帧步进（12 步/18ms）是否满足所有目标应用的拖放识别？ | 拖放可靠性 | 未遇到反例 |
