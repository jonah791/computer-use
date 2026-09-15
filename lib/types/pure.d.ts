/**
 * computer-use 的纯逻辑（零 IO，可离线单测）：注入安全闸、helper 输出解析、参数构造。
 *
 * 这一层存在的理由：把「决策」从 spawn/进程/文件系统里搬出来，
 * 让安全闸与解析逻辑能被**没有桌面环境**的测试直接证伪（见 tests/pure.test.mjs）。
 */
/** 前台窗口形状（helper 的 Get-ForegroundInfo 输出）。 */
export interface ForegroundInfo {
    hwnd: number;
    title: string;
    process?: string;
    pid?: number;
}
/** 注入类调用的目标声明。 */
export interface ExpectTarget {
    expectWindow?: string;
    expectHwnd?: number;
    allowAnyWindow?: boolean;
}
export type GuardCode = 'ok' | 'no-expect' | 'no-foreground' | 'mismatch';
export interface GuardDecision {
    allowed: boolean;
    code: GuardCode;
    reason: string;
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
export declare function decideInjectionGuard(expect: ExpectTarget, foreground: ForegroundInfo | null): GuardDecision;
/** 把目标声明翻译成 helper 的命令行旗标。 */
export declare function injectionFlagArgs(expect: ExpectTarget): string[];
export interface HelperResult {
    ok: boolean;
    stage?: string;
    error?: string;
    data: Record<string, unknown>;
}
/**
 * 解析 helper 的 stdout。取最后一行非空输出（helper 只 emit 一行 JSON）；
 * 无输出 / 非 JSON / exit≠0 都要给出**可诊断**的失败原因（stderr 摘要入错误信息）。
 */
export declare function parseHelperJson(stdout: string, stderr: string, exitCode: number | null): HelperResult;
/** 文本 → base64(UTF-8)：命令行不传原始文本，避免编码与转义丢失。 */
export declare function toBase64Utf8(text: string): string;
/** 截图缩放系数：非法值回落；上限 1（放大没有意义）。 */
export declare function normalizeScale(value: unknown, fallback?: number): number;
export type ShotMode = 'full' | 'region' | 'window';
export interface ShotSpec {
    outPath: string;
    mode: ShotMode;
    scale?: number;
    region?: {
        x: number;
        y: number;
        w: number;
        h: number;
    };
    windowHwnd?: number;
}
/**
 * 构造 shot 命令的参数数组。
 * `--region` 的值必须是**单个** argv 元素 `x,y,w,h`（命令行走 spawn 数组，不经 shell，无需引号）。
 * 2026-09-15 实测坑：在 PowerShell 里手输 `300,1150,2200,320` 会被解析成数组并压成空格分隔串 ⇒ 帮助器报 Int32 转换失败。
 */
export declare function buildShotArgs(spec: ShotSpec): string[];
/** 截图落盘路径：未指定时按时间戳生成，避免并发/连续调用互相覆盖。 */
export declare function buildShotPath(dir: string, mode: ShotMode, ts: number): string;
/** 参数摘要（仅形状，**绝不记录被输入的文本**——隐私纪律）。 */
export declare function summarizeForTrace(args: Record<string, unknown>): Record<string, unknown>;
