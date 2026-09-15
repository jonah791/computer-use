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
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
export declare const name = "agent-computer-use";
export declare const inject: readonly ["tools"];
export interface Config {
    enabled: boolean;
    interpreter: string;
    helperPath: string;
    shotDir: string;
    tracePath: string;
    timeoutMs: number;
}
export declare const Config: z<Schemastery.ObjectS<{
    enabled: z<boolean, boolean>;
    /** 本机实测：pwsh 不在 PATH，唯一解释器是 Windows PowerShell 5.1。 */
    interpreter: z<string, string>;
    /** 留空则按插件目录解析 `<pkg>/helper/cu-helper.ps1`。 */
    helperPath: z<string, string>;
    shotDir: z<string, string>;
    tracePath: z<string, string>;
    timeoutMs: z<number, number>;
}>, Schemastery.ObjectT<{
    enabled: z<boolean, boolean>;
    /** 本机实测：pwsh 不在 PATH，唯一解释器是 Windows PowerShell 5.1。 */
    interpreter: z<string, string>;
    /** 留空则按插件目录解析 `<pkg>/helper/cu-helper.ps1`。 */
    helperPath: z<string, string>;
    shotDir: z<string, string>;
    tracePath: z<string, string>;
    timeoutMs: z<number, number>;
}>>;
export declare function apply(ctx: Context, config: Config): void;
