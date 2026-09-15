# computer-use

> 让主脑（爱丽丝）**自己看屏幕、自己操作鼠标键盘**——从而独立走完「开发 → 验证 → 迭代」闭环，
> 不必再由主人充当眼睛和手。

DSH 插件（host-only）。6 个工具：截屏 · 窗口清单 · 聚焦 · 鼠标 · 键盘 · 环境自检。

## 为什么是它

改了 GUI 却要等主人帮忙看一眼，迭代速度就被"人"卡住了。本插件把 GUI 世界的**感知**（截屏 → 亲眼看）
与**行动**（鼠标键盘注入）变成工具面的一部分，闭环从此在我的循环里跑完。

## 工具

| 工具 | 说明 |
|---|---|
| `cu_probe` | 环境自检：屏幕 / 坐标空间 / DPI 声明 / 光标 / 前台窗口 / 窗口总数。行为异常时**第一个**调用它 |
| `cu_screen` | 截屏落盘（全屏 / 矩形 / 指定窗口，可缩放）→ 返回路径，交给官方的 `read_image` 亲眼看 |
| `cu_windows` | 窗口清单（标题 / 进程 / 位置 / 可见）或定点查询「这个坐标上是哪个窗口」 |
| `cu_focus` | 把窗口切到前台 |
| `cu_mouse` | move / click / double / drag / scroll |
| `cu_key` | 组合键（`ctrl+s`）与 Unicode 文本（中文也可）；`verifyKey` 可读回状态自证 |

坐标一律**物理像素**，与截图像素同空间——**一格不用换算**。

## 安全（重要）

`cu_mouse` / `cu_key` 是**注入类**工具，必须声明目标窗口：

```
cu_key({ keys: "ctrl+s", expectWindow: "Notepad" })     // 前台不是该窗口 → 拒绝执行
cu_mouse({ action: "click", x: 100, y: 200, expectHwnd: 123456 })
```

- 前台与期望不符 → 返回 `INJECTION_REFUSED`（**fail-closed**）；
- 确有需要时用 `allowAnyWindow: true` 显式放行；
- 闸有两层：工具面静态闸（判"有没有打算"）+ helper 原子闸（注入前一刻复核前台，防"打算了但前台被换掉"）。
- 这条不是凭空加的：2026-09-15 实测事故——测试脚本没找到目标却没停，39 个字符被注入到主人正在使用的窗口。

## 技术要点（改代码前先读）

1. **不落盘 exe**：本机 Defender ASR 规则 `01443614-…` 禁止运行「全新未签名可执行文件」
   （实测拦截我们自己编译的 probe.exe，事件 ID 1121）⇒ native 层只能 `Add-Type` 内存编译，
   helper 必须保持 `.ps1 + .cs` 形态，**不要"优化"成 exe**。
2. **坐标一律物理像素**：PowerShell 5.1 默认 DPI-unaware（1707×1067 逻辑空间），
   helper 加载时调 `SetProcessDPIAware()`，之后光标读/写与截图同空间（实测 665 × 1.5 = 998）。
3. **每次调用独立进程**：实测端到端 528ms（含进程启动 + C# 内存编译），无状态、无保活负担。
4. **注入前验靶**：见上「安全」。

## 配置

| 项 | 默认 | 说明 |
|---|---|---|
| `interpreter` | `C:/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe` | 本机唯一可用解释器（`pwsh` 不在 PATH） |
| `helperPath` | 空（按插件目录解析） | `helper/cu-helper.ps1` |
| `shotDir` | `E:/alice/_tmp_review/cu-shots` | 截图输出目录 |
| `tracePath` | `E:/alice/.dsh/computer-use-trace.jsonl` | 侧车轨迹（一行一阶段） |
| `timeoutMs` | `30000` | 单次 helper 调用超时 |

## 测试

```powershell
pnpm build && pnpm test        # 14 例纯逻辑单测（无需桌面）
node tests/smoke-helper.mjs    # 本机冒烟：能力 + 安全闸尸体测试 + 注入闭环（需桌面）
```

## 契约与边界

- 语义文档（不变量 / 契约 / 可证伪验收 / 未决问题）：`docs/semantic.md`
- **能力 ≠ 沙箱**：本插件提供真实输入注入能力，与宿主同权限，不是安全边界。
- 注入成功 ≠ 目标应用接受（模态框、焦点抢占、UAC 提权窗口无法注入）。
- Windows 可能阻止后台进程抢焦点：`cu_focus` 的 `apiOk` 只是 API 返回值，**以返回的 `foreground` 为准**。

## License

MIT
