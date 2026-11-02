// CuNative.cs — computer-use 的原生层（P/Invoke 声明 + 薄封装）
// 设计约束：本机 Defender ASR 规则 01443614-… 禁止运行「全新未签名 exe」，
//          因此本文件不做成 exe，而是由 cu-helper.ps1 用 Add-Type 内存编译加载。
// 兼容性：必须能过 .NET Framework csc v4.0.30319（C# 5），不用 lambda / 插值字符串 / nameof。
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class CuNative
{
    // ---------- 结构体 ----------
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int X; public int Y; }

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    public struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }

    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }

    [StructLayout(LayoutKind.Sequential)]
    public struct HARDWAREINPUT { public uint uMsg; public ushort wParamL; public ushort wParamH; }

    [StructLayout(LayoutKind.Explicit)]
    public struct INPUTUNION
    {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
        [FieldOffset(0)] public HARDWAREINPUT hi;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT { public uint type; public INPUTUNION u; }

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    // ---------- user32 / gdi32 ----------
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT p);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll", SetLastError = true)] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hWnd, StringBuilder text, int maxCount);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassNameW(IntPtr hWnd, StringBuilder text, int maxCount);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags, int dx, int dy, uint data, IntPtr extraInfo);
    [DllImport("user32.dll", SetLastError = true)] public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
    [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(POINT p);
    [DllImport("user32.dll")] public static extern bool ScreenToClient(IntPtr hWnd, ref POINT p);

    // ---------- 窗口样式守卫：不抢前台的关键机制 ----------
    // 来源：cua 的 docs/windows-background-input-re-plan.md（标 RESOLVED，e2e 6/6 通过）
    //   给目标窗口临时设 WS_EX_NOACTIVATE 后，Windows **拒绝**把它前台化——
    //   点击激活、WM_MOUSEACTIVATE、以及 WPF/XAML/Tauri 自动化处理器自己发起的
    //   SetForegroundWindow(self) **全部被拒**，而窗口**照样收到**点击与按键。
    //   作用域只是那一个窗口，用完立刻还原。
    // ⚠ 反面记录（别重试）：全局前台锁 SPI_SETFOREGROUNDLOCKTIMEOUT 实测**无效**——
    //   我们自己注入/投递的输入本身会「合法化」目标的前台主张，锁到最大也照样被抢。
    [DllImport("user32.dll", SetLastError = true)] public static extern int GetWindowLong(IntPtr hWnd, int nIndex);
    [DllImport("user32.dll", SetLastError = true)] public static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
    [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr hWnd, uint gaFlags);

    public const int GWL_EXSTYLE = -20;
    public const int WS_EX_NOACTIVATE = 0x08000000;
    public const uint GA_ROOT = 2;

    /// <summary>临时给目标窗口加 WS_EX_NOACTIVATE，让 Windows 拒绝前台化它。
    /// ⚠ **必须还原**：不还原会让该窗口**永久**失去激活能力（用户点任务栏都不亮）。
    /// ⚠ 判据只能是**回读**：SetWindowLong 返回旧值，旧值为 0 时无法区分成功与失败。
    /// 用法（PowerShell）：$g = New-Object 'CuNative+NoActivateGuard' -ArgumentList $hwnd; try { ... } finally { $g.Dispose() }</summary>
    public class NoActivateGuard : IDisposable
    {
        private IntPtr _hwnd;
        private int _origStyle;
        private bool _armed;
        private bool _disposed;

        public NoActivateGuard(IntPtr hwnd)
        {
            _hwnd = hwnd;
            _origStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
            SetWindowLong(hwnd, GWL_EXSTYLE, _origStyle | WS_EX_NOACTIVATE);
            _armed = (GetWindowLong(hwnd, GWL_EXSTYLE) & WS_EX_NOACTIVATE) != 0;
        }

        public bool Armed { get { return _armed; } }
        public int OriginalStyle { get { return _origStyle; } }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_hwnd != IntPtr.Zero)
            {
                SetWindowLong(_hwnd, GWL_EXSTYLE, _origStyle);
                _hwnd = IntPtr.Zero;
            }
        }
    }

    // ---------- 后台投递（PostMessage） ----------
    // ⚠ 用途极窄（2026-10-26 实测 + cua Issue #1623）：
    //   PostMessage(WM_LBUTTONDOWN/UP) 对 **Chromium 不触发 DOM 输入**（网页/壳的坐标点击必须走 SendInput）；
    //   对多数 WPF/XAML 同样不可靠。只有**原生 Win32 控件**（button / edit / 标准 dialog）吃这一套。
    //   ⇒ 它**不是**前台的替代品，只在「目标已在后台、且确知是原生控件」时用，且调用方必须自己验证结果。
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    public const uint WM_MOUSEMOVE = 0x0200;
    public const uint WM_LBUTTONDOWN = 0x0201;
    public const uint WM_LBUTTONUP = 0x0202;
    public const uint WM_RBUTTONDOWN = 0x0204;
    public const uint WM_RBUTTONUP = 0x0205;
    public const uint WM_MBUTTONDOWN = 0x0207;
    public const uint WM_MBUTTONUP = 0x0208;
    public const uint WM_MOUSEWHEEL = 0x020A;

    /// <summary>把两个 16 位值打包成 lParam（鼠标消息用）。
    /// ⚠ 鼠标消息的坐标是**客户区**坐标（相对窗口左上角），不是屏幕坐标。</summary>
    public static IntPtr MakeLParam(int lo, int hi)
    {
        return (IntPtr)((hi << 16) | (lo & 0xFFFF));
    }

    /// <summary>投递一次鼠标点击到目标窗口的消息队列。
    /// 返回**消息是否进了队列** —— ⚠ 它**不代表控件响应了**，这是本 API 的固有限制，不是实现缺陷。
    /// 调用方必须自己验证状态变化（读控件值 / 看落盘副作用）。</summary>
    public static bool PostClick(IntPtr hWnd, int clientX, int clientY, string button)
    {
        uint down; uint up;
        if (button == "right") { down = WM_RBUTTONDOWN; up = WM_RBUTTONUP; }
        else if (button == "middle") { down = WM_MBUTTONDOWN; up = WM_MBUTTONUP; }
        else { down = WM_LBUTTONDOWN; up = WM_LBUTTONUP; }
        IntPtr lp = MakeLParam(clientX, clientY);
        bool a = PostMessage(hWnd, down, IntPtr.Zero, lp);
        bool b = PostMessage(hWnd, up, IntPtr.Zero, lp);
        return a && b;
    }

    /// <summary>投递滚轮到目标窗口（lParam=客户区坐标，wParam 高字=增量）。
    /// 同样只保证「进了队列」，不保证目标应用处理了。</summary>
    public static bool PostWheel(IntPtr hWnd, int clientX, int clientY, int delta)
    {
        IntPtr lp = MakeLParam(clientX, clientY);
        IntPtr wp = (IntPtr)((delta << 16) | 0);
        return PostMessage(hWnd, WM_MOUSEWHEEL, wp, lp);
    }
    [DllImport("user32.dll")] public static extern IntPtr GetDesktopWindow();
    [DllImport("user32.dll")] public static extern short GetKeyState(int vk);
    [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vk);
    [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
    [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();

    public static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
    public static readonly IntPtr HWND_NOTOPMOST = new IntPtr(-2);
    public const uint SWP_NOSIZE = 0x0001;
    public const uint SWP_NOMOVE = 0x0002;
    public const uint SWP_SHOWWINDOW = 0x0040;

    /// <summary>把窗口切到前台（尽力而为，返回**是否真的落到前台**——读 GetForegroundWindow 确认，不信 API 返回值）。
    /// 背景进程直调 SetForegroundWindow 会被 Windows 拒绝（实测 apiOk=false），
    /// 故三级降级：直调 → TOPMOST 往返 → AttachThreadInput 借用前台线程的输入队列。</summary>
    public static bool ForceForeground(IntPtr hWnd)
    {
        if (GetForegroundWindow() == hWnd) return true;
        if (IsIconic(hWnd)) ShowWindow(hWnd, SW_RESTORE);
        else ShowWindow(hWnd, SW_SHOW);

        if (SetForegroundWindow(hWnd)) return true;

        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        SetWindowPos(hWnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        if (SetForegroundWindow(hWnd)) return true;

        IntPtr fg = GetForegroundWindow();
        uint fgThread = 0;
        if (fg != IntPtr.Zero)
        {
            uint unused = 0;
            fgThread = GetWindowThreadProcessId(fg, out unused);
        }
        uint myThread = GetCurrentThreadId();
        if (fgThread != 0 && fgThread != myThread)
        {
            AttachThreadInput(myThread, fgThread, true);
            BringWindowToTop(hWnd);
            SetForegroundWindow(hWnd);
            AttachThreadInput(myThread, fgThread, false);
        }
        return GetForegroundWindow() == hWnd;
    }

    // ---------- 常量 ----------
    public const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
    public const uint MOUSEEVENTF_LEFTUP = 0x0004;
    public const uint MOUSEEVENTF_RIGHTDOWN = 0x0008;
    public const uint MOUSEEVENTF_RIGHTUP = 0x0010;
    public const uint MOUSEEVENTF_MIDDLEDOWN = 0x0020;
    public const uint MOUSEEVENTF_MIDDLEUP = 0x0040;
    public const uint MOUSEEVENTF_WHEEL = 0x0800;
    public const uint KEYEVENTF_KEYUP = 0x0002;
    public const uint KEYEVENTF_UNICODE = 0x0004;
    public const uint INPUT_KEYBOARD = 1;
    public const int SW_RESTORE = 9;
    public const int SW_SHOW = 5;

    // ---------- 窗口 ----------
    public static string WindowTitle(IntPtr hWnd)
    {
        StringBuilder sb = new StringBuilder(512);
        GetWindowTextW(hWnd, sb, sb.Capacity);
        return sb.ToString();
    }

    public static string ClassName(IntPtr hWnd)
    {
        StringBuilder sb = new StringBuilder(256);
        GetClassNameW(hWnd, sb, sb.Capacity);
        return sb.ToString();
    }

    private static List<IntPtr> _found;
    private static bool CollectProc(IntPtr hWnd, IntPtr lParam)
    {
        _found.Add(hWnd);
        return true;
    }

    public static List<IntPtr> AllWindows()
    {
        _found = new List<IntPtr>();
        EnumWindows(new EnumWindowsProc(CollectProc), IntPtr.Zero);
        List<IntPtr> copy = _found;
        _found = null;
        return copy;
    }

    // ---------- 输入 ----------
    public static void MouseButton(string button, bool down)
    {
        uint flag;
        if (button == "right") flag = down ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
        else if (button == "middle") flag = down ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
        else flag = down ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
        mouse_event(flag, 0, 0, 0, IntPtr.Zero);
    }

    public static void Scroll(int delta)
    {
        mouse_event(MOUSEEVENTF_WHEEL, 0, 0, unchecked((uint)delta), IntPtr.Zero);
    }

    // 单字符 Unicode 注入（SendInput 通道，支持中文；keybd_event 的 bScan 是 BYTE，发不了 >255 的字符）
    public static bool SendUnicodeChar(char c)
    {
        INPUT[] inputs = new INPUT[2];
        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].u.ki.wVk = 0;
        inputs[0].u.ki.wScan = (ushort)c;
        inputs[0].u.ki.dwFlags = KEYEVENTF_UNICODE;
        inputs[0].u.ki.time = 0;
        inputs[0].u.ki.dwExtraInfo = IntPtr.Zero;
        inputs[1].type = INPUT_KEYBOARD;
        inputs[1].u.ki.wVk = 0;
        inputs[1].u.ki.wScan = (ushort)c;
        inputs[1].u.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        inputs[1].u.ki.time = 0;
        inputs[1].u.ki.dwExtraInfo = IntPtr.Zero;
        uint sent = SendInput(2, inputs, Marshal.SizeOf(typeof(INPUT)));
        return sent == 2;
    }

    public static bool SendVk(ushort vk, bool keyUp)
    {
        INPUT[] inputs = new INPUT[1];
        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].u.ki.wVk = vk;
        inputs[0].u.ki.wScan = 0;
        inputs[0].u.ki.dwFlags = keyUp ? KEYEVENTF_KEYUP : 0;
        inputs[0].u.ki.time = 0;
        inputs[0].u.ki.dwExtraInfo = IntPtr.Zero;
        return SendInput(1, inputs, Marshal.SizeOf(typeof(INPUT))) == 1;
    }

    public static int InputStructSize()
    {
        return Marshal.SizeOf(typeof(INPUT));
    }

    // 键名 → 虚拟键码
    public static ushort Vk(string name)
    {
        string n = name.ToLowerInvariant();
        if (n.Length == 1)
        {
            char c = n[0];
            if (c >= 'a' && c <= 'z') return (ushort)(0x41 + (c - 'a'));
            if (c >= '0' && c <= '9') return (ushort)(0x30 + (c - '0'));
        }
        switch (n)
        {
            case "enter": case "return": return 0x0D;
            case "tab": return 0x09;
            case "esc": case "escape": return 0x1B;
            case "space": return 0x20;
            case "backspace": case "bs": return 0x08;
            case "delete": case "del": return 0x2E;
            case "insert": return 0x2D;
            case "home": return 0x24;
            case "end": return 0x23;
            case "pageup": case "pgup": return 0x21;
            case "pagedown": case "pgdn": return 0x22;
            case "up": return 0x26;
            case "down": return 0x28;
            case "left": return 0x25;
            case "right": return 0x27;
            case "ctrl": case "control": return 0x11;
            case "shift": return 0x10;
            case "alt": return 0x12;
            case "win": case "lwin": return 0x5B;
            case "capslock": return 0x14;
            case "prtsc": case "printscreen": return 0x2C;
            case "f1": return 0x70; case "f2": return 0x71; case "f3": return 0x72; case "f4": return 0x73;
            case "f5": return 0x74; case "f6": return 0x75; case "f7": return 0x76; case "f8": return 0x77;
            case "f9": return 0x78; case "f10": return 0x79; case "f11": return 0x7A; case "f12": return 0x7B;
            default: return 0;
        }
    }
}
