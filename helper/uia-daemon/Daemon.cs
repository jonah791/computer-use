// cu-uia-daemon — a UIAccess-capable resident UIA worker for the computer-use plugin.
//
// WHY A DAEMON (measured 2026-10-26, this machine):
//   The manifest must say level="highestAvailable" (asInvoker + uiAccess="true" is
//   rejected with ERROR_ELEVATION_REQUIRED). A highestAvailable binary therefore
//   needs elevation every launch. From a Medium-IL caller this BLOCKS on the UAC
//   prompt: measured launch=FAILED "操作已被用户取消", elapsed 122367 ms, no output.
//   => Spawning per call is unusable. Start once as admin, then talk over TCP.
//
// WHY UIAccess AT ALL (measured 2026-10-26):
//   WS_EX_NOACTIVATE does NOT stop UIA Select(): the guard was armed and the
//   foreground still got stolen (stolenWhileGuarded=true). Select() reaches the
//   target through the keyboard-focus path, not through "user clicked / SWP".
//   UIAccess lifts that restriction; as a bonus SetForegroundWindow succeeds, so
//   we can hand the foreground back if the target steals it anyway.
//
// Wire protocol: one request line, one response line, both UTF-8, fields separated
//   by '|', each field "key=value". Free-text values are base64(UTF-8) so that
//   Chinese, quotes, pipes and newlines need no escaping.
//     request : token=<t>|sub=<cmd>|hwnd=<n>|name=<b64>|text=<b64>|max=<n>|restore=<0|1>
//     response: a single-line JSON object
//
// Commands: probe | list | invoke | setvalue | select | fg | restore | stop
//
// Compile with the in-box .NET 4 csc (C# 5 only — no string interpolation, no ?.).

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Automation;

namespace AliceUIA
{
    internal static class J
    {
        public static string S(string v)
        {
            if (v == null) return "null";
            StringBuilder sb = new StringBuilder(v.Length + 16);
            sb.Append('"');
            for (int i = 0; i < v.Length; i++)
            {
                char c = v[i];
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    default:
                        if (c < ' ')
                        {
                            sb.Append("\\u");
                            sb.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        public static string B(bool b) { return b ? "true" : "false"; }
        public static string N(long n) { return n.ToString(CultureInfo.InvariantCulture); }
    }

    internal static class Daemon
    {
        public const string Version = "1.0.0";

        // ---------------------------------------------------------------- Win32
        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool IsWindow(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder buf, int max);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetClassNameW(IntPtr hWnd, StringBuilder buf, int max);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr token, int cls, out uint info, int len, out int ret);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentProcessId();

        [DllImport("kernel32.dll")]
        private static extern bool ProcessIdToSessionId(uint pid, out uint sid);

        private static int ReadUIAccess()
        {
            IntPtr tok;
            if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out tok)) return -1;
            uint val;
            int ret;
            if (!GetTokenInformation(tok, 26, out val, 4, out ret)) return -2;
            return (int)val;
        }

        private static string WinText(IntPtr hWnd)
        {
            if (hWnd == IntPtr.Zero) return "";
            StringBuilder sb = new StringBuilder(768);
            int n = GetWindowTextW(hWnd, sb, sb.Capacity);
            return n <= 0 ? "" : sb.ToString(0, n);
        }

        private static string WinClass(IntPtr hWnd)
        {
            if (hWnd == IntPtr.Zero) return "";
            StringBuilder sb = new StringBuilder(512);
            int n = GetClassNameW(hWnd, sb, sb.Capacity);
            return n <= 0 ? "" : sb.ToString(0, n);
        }

        private static uint WinPid(IntPtr hWnd)
        {
            uint pid;
            GetWindowThreadProcessId(hWnd, out pid);
            return pid;
        }

        private static string ProcNameOf(IntPtr hWnd)
        {
            uint pid = WinPid(hWnd);
            if (pid == 0) return "";
            try
            {
                using (System.Diagnostics.Process p = System.Diagnostics.Process.GetProcessById((int)pid))
                {
                    return p.ProcessName;
                }
            }
            catch { return ""; }
        }

        // ---------------------------------------------------------------- config
        private static string _token = "";
        private static int _port = 8444;
        private static string _dataDir = "";
        private static string _logPath = "";
        private static TcpListener _listener;
        private static volatile bool _stopping = false;
        private static readonly object _logLock = new object();

        private static void Log(string msg)
        {
            string line = DateTime.Now.ToString("s", CultureInfo.InvariantCulture) + "  " + msg;
            try
            {
                lock (_logLock)
                {
                    if (_logPath != null && _logPath.Length > 0)
                    {
                        File.AppendAllText(_logPath, line + Environment.NewLine, Encoding.UTF8);
                    }
                }
            }
            catch { }
        }

        // ---------------------------------------------------------------- main
        private static int Main(string[] args)
        {
            string dataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AliceUIA");
            int port = 8444;
            bool probeOnly = false;
            bool foregroundStart = false;

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (a == "--port" && i + 1 < args.Length) { int.TryParse(args[++i], out port); }
                else if (a == "--data-dir" && i + 1 < args.Length) { dataDir = args[++i]; }
                else if (a == "--probe-only") { probeOnly = true; }
                else if (a == "--foreground") { foregroundStart = true; }
            }

            _port = port;
            _dataDir = dataDir;
            try { Directory.CreateDirectory(dataDir); } catch { }
            _logPath = Path.Combine(dataDir, "daemon.log");

            if (foregroundStart)
            {
                try { AllocConsole(); } catch { }
            }

            int uiaToken = ReadUIAccess();
            uint sid;
            ProcessIdToSessionId(GetCurrentProcessId(), out sid);

            int chk = 0;
            string chkDetail = "";
            chkDetail = Preflight(uiaToken, out chk);

            // ---- probe-only: dump the self-check and exit (used by the installer)
            if (probeOnly)
            {
                string p = Path.Combine(dataDir, "probe-result.json");
                string body = BuildProbeJson(uiaToken, sid, chkDetail);
                try { File.WriteAllText(p, body + Environment.NewLine, new UTF8Encoding(false)); } catch { }
                Log("probe-only: uiAccessToken=" + uiaToken + " session=" + sid);
                try { Console.WriteLine(body); } catch { }
                return uiaToken == 1 ? 0 : 3;
            }

            // ---- token: reuse if present, else mint once
            string tokenPath = Path.Combine(dataDir, "token.txt");
            try
            {
                if (File.Exists(tokenPath))
                {
                    string t = File.ReadAllText(tokenPath).Trim();
                    if (t.Length >= 16) _token = t;
                }
                if (_token.Length == 0)
                {
                    byte[] raw = new byte[24];
                    using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider()) { rng.GetBytes(raw); }
                    _token = BitConverter.ToString(raw).Replace("-", "").ToLowerInvariant();
                    File.WriteAllText(tokenPath, _token, new UTF8Encoding(false));
                    Log("minted new token");
                }
            }
            catch (Exception ex)
            {
                Log("token setup FAILED: " + ex.Message);
                return 4;
            }

            // ---- bind: try the requested port, then walk upward a little
            Exception bindErr = null;
            for (int attempt = 0; attempt < 12; attempt++)
            {
                int tryPort = port + attempt;
                try
                {
                    _listener = new TcpListener(IPAddress.Loopback, tryPort);
                    _listener.Start();
                    _port = tryPort;
                    bindErr = null;
                    break;
                }
                catch (Exception ex)
                {
                    bindErr = ex;
                    try { if (_listener != null) _listener.Stop(); } catch { }
                    _listener = null;
                }
            }
            if (_listener == null)
            {
                Log("bind FAILED on ports " + port + ".." + (port + 11) + ": " + (bindErr == null ? "?" : bindErr.Message));
                return 5;
            }

            // ---- status file: the client uses this to find us
            string statusPath = Path.Combine(dataDir, "daemon-status.json");
            try
            {
                File.WriteAllText(statusPath, BuildProbeJson(uiaToken, sid, chkDetail) + Environment.NewLine,
                    new UTF8Encoding(false));
            }
            catch (Exception ex) { Log("status write failed: " + ex.Message); }

            Log("listening on 127.0.0.1:" + _port + "  uiAccessToken=" + uiaToken + "  session=" + sid
                + "  pid=" + GetCurrentProcessId() + "  version=" + Version);

            // ---- serve until asked to stop
            while (!_stopping)
            {
                TcpClient client = null;
                try
                {
                    client = _listener.AcceptTcpClient();
                    ThreadPool.QueueUserWorkItem(HandleClientThunk, client);
                    client = null; // ownership passed to the worker
                }
                catch (Exception ex)
                {
                    if (_stopping) break;
                    Log("accept error: " + ex.Message);
                    if (client != null) { try { client.Close(); } catch { } }
                    Thread.Sleep(200);
                }
            }

            Log("serve loop exited");
            return 0;
        }

        [DllImport("kernel32.dll")]
        private static extern bool AllocConsole();

        private static void HandleClientThunk(object state)
        {
            HandleClient((TcpClient)state);
        }

        // ---------------------------------------------------------------- preflight
        private static string Preflight(int uiaToken, out int code)
        {
            StringBuilder sb = new StringBuilder(256);
            code = 0;
            sb.Append("uiAccess=").Append(uiaToken);
            if (uiaToken == 1) { sb.Append(" (OK)"); }
            else { sb.Append(" (MISSING: expect elevation+signature+secure-path all at once)"); code |= 1; }

            string exe = "";
            try { exe = System.Reflection.Assembly.GetExecutingAssembly().Location; } catch { }
            bool inSecurePath = false;
            try
            {
                string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
                string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                inSecurePath =
                    (pf.Length > 0 && exe.StartsWith(pf, StringComparison.OrdinalIgnoreCase)) ||
                    (pf86.Length > 0 && exe.StartsWith(pf86, StringComparison.OrdinalIgnoreCase)) ||
                    (win.Length > 0 && exe.StartsWith(win, StringComparison.OrdinalIgnoreCase));
            }
            catch { }
            sb.Append(";securePath=").Append(inSecurePath ? "1" : "0");
            if (!inSecurePath) code |= 2;

            IntPtr fg = GetForegroundWindow();
            sb.Append(";desktopVisible=").Append(fg != IntPtr.Zero ? "1" : "0");
            if (fg == IntPtr.Zero) code |= 4;

            return sb.ToString();
        }

        private static string BuildProbeJson(int uiaToken, uint sid, string chkDetail)
        {
            string exe = "";
            try { exe = System.Reflection.Assembly.GetExecutingAssembly().Location; } catch { }
            string user = "";
            try { user = Environment.UserName; } catch { }
            IntPtr fg = GetForegroundWindow();

            StringBuilder sb = new StringBuilder(512);
            sb.Append('{');
            sb.Append("\"ok\":").Append(J.B(uiaToken == 1)).Append(',');
            sb.Append("\"tool\":\"cu-uia-daemon\"").Append(',');
            sb.Append("\"version\":").Append(J.S(Version)).Append(',');
            sb.Append("\"uiAccessToken\":").Append(J.N(uiaToken)).Append(',');
            sb.Append("\"verdict\":").Append(J.S(uiaToken == 1 ? "UIAccess ACTIVE" : "UIAccess NOT active")).Append(',');
            sb.Append("\"pid\":").Append(J.N(GetCurrentProcessId())).Append(',');
            sb.Append("\"sessionId\":").Append(J.N(sid)).Append(',');
            sb.Append("\"port\":").Append(J.N(_port)).Append(',');
            sb.Append("\"user\":").Append(J.S(user)).Append(',');
            sb.Append("\"exe\":").Append(J.S(exe)).Append(',');
            sb.Append("\"check\":").Append(J.S(chkDetail)).Append(',');
            sb.Append("\"foregroundHwnd\":").Append(J.N(fg.ToInt64())).Append(',');
            sb.Append("\"foregroundTitle\":").Append(J.S(WinText(fg))).Append(',');
            sb.Append("\"startedAt\":").Append(J.S(DateTime.Now.ToString("s", CultureInfo.InvariantCulture)));
            sb.Append('}');
            return sb.ToString();
        }

        // ---------------------------------------------------------------- protocol
        private static readonly Dictionary<string, string> Empty = new Dictionary<string, string>();

        private static void HandleClient(TcpClient client)
        {
            try
            {
                using (client)
                {
                    client.ReceiveTimeout = 20000;
                    client.SendTimeout = 20000;
                    using (NetworkStream ns = client.GetStream())
                    {
                        string line = ReadLine(ns);
                        string resp;
                        if (line == null)
                        {
                            resp = "{\"ok\":false,\"error\":\"empty request\"}";
                        }
                        else
                        {
                            Dictionary<string, string> f;
                            try { f = ParseFields(line); }
                            catch (Exception ex)
                            {
                                f = Empty;
                                resp = "{\"ok\":false,\"error\":" + J.S("bad request: " + ex.Message) + "}";
                                WriteLine(ns, resp);
                                return;
                            }
                            resp = Dispatch(f);
                        }
                        WriteLine(ns, resp);
                    }
                }
            }
            catch (Exception ex)
            {
                Log("client error: " + ex.Message);
            }
        }

        private static string ReadLine(NetworkStream ns)
        {
            List<byte> buf = new List<byte>(256);
            int b;
            while ((b = ns.ReadByte()) >= 0)
            {
                if (b == '\n') break;
                if (b == '\r') continue;
                buf.Add((byte)b);
                if (buf.Count > 4 * 1024 * 1024) throw new Exception("request too large");
            }
            if (buf.Count == 0) return null;
            return Encoding.UTF8.GetString(buf.ToArray());
        }

        private static void WriteLine(NetworkStream ns, string s)
        {
            byte[] data = Encoding.UTF8.GetBytes(s + "\n");
            ns.Write(data, 0, data.Length);
            ns.Flush();
        }

        private static Dictionary<string, string> ParseFields(string line)
        {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string[] parts = line.Split('|');
            for (int i = 0; i < parts.Length; i++)
            {
                string p = parts[i];
                if (p.Length == 0) continue;
                int eq = p.IndexOf('=');
                if (eq <= 0) continue;
                d[p.Substring(0, eq)] = p.Substring(eq + 1);
            }
            return d;
        }

        private static string Field(Dictionary<string, string> f, string key)
        {
            string v;
            return f.TryGetValue(key, out v) ? v : "";
        }

        private static long FieldLong(Dictionary<string, string> f, string key, long dflt)
        {
            long n;
            string v = Field(f, key);
            if (v.Length == 0) return dflt;
            return long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out n) ? n : dflt;
        }

        private static string FieldB64(Dictionary<string, string> f, string key)
        {
            string v = Field(f, key);
            if (v.Length == 0) return "";
            try { return Encoding.UTF8.GetString(Convert.FromBase64String(v)); }
            catch { return ""; } // caller decides whether empty means "wrong encoding"
        }

        private static string Dispatch(Dictionary<string, string> f)
        {
            string sub = Field(f, "sub");
            if (sub.Length == 0) sub = "probe";

            // 'probe' is deliberately token-free so health checks need no secret.
            if (sub == "probe")
            {
                uint sid;
                ProcessIdToSessionId(GetCurrentProcessId(), out sid);
                int chk;
                string detail = Preflight(ReadUIAccess(), out chk);
                return BuildProbeJson(ReadUIAccess(), sid, detail);
            }

            if (Field(f, "token") != _token)
            {
                Log("REJECTED bad token for sub=" + sub);
                return "{\"ok\":false,\"error\":\"bad token\"}";
            }

            IntPtr hwnd = new IntPtr(FieldLong(f, "hwnd", 0));
            string name = FieldB64(f, "name");
            string text = FieldB64(f, "text");
            int max = (int)FieldLong(f, "max", 60);
            if (max <= 0) max = 60;
            bool wantRestore = FieldLong(f, "restore", 1) != 0;
            bool force = FieldLong(f, "force", 0) != 0;

            try
            {
                if (sub == "list") return DoList(hwnd, max);
                if (sub == "invoke" || sub == "setvalue" || sub == "select")
                    return DoAction(sub, hwnd, name, text, wantRestore, force);
                if (sub == "fg") return DoForeground();
                if (sub == "restore") return DoRestore(hwnd);
                if (sub == "stop")
                {
                    Log("stop requested");
                    _stopping = true;
                    ThreadPool.QueueUserWorkItem(delegate(object o)
                    {
                        Thread.Sleep(150);
                        try { if (_listener != null) _listener.Stop(); } catch { }
                        Environment.Exit(0);
                    }, null);
                    return "{\"ok\":true,\"stopping\":true}";
                }
                return "{\"ok\":false,\"error\":" + J.S("unknown sub: " + sub) + "}";
            }
            catch (Exception ex)
            {
                return "{\"ok\":false,\"error\":" + J.S(ex.GetType().Name + ": " + ex.Message) + "}";
            }
        }

        // ---------------------------------------------------------------- ops
        private static AutomationElement Root(IntPtr hwnd)
        {
            if (hwnd == IntPtr.Zero) throw new Exception("hwnd is 0");
            if (!IsWindow(hwnd)) throw new Exception("hwnd " + hwnd.ToInt64() + " is not a window");
            AutomationElement el;
            try { el = AutomationElement.FromHandle(hwnd); }
            catch (Exception ex) { throw new Exception("FromHandle failed for hwnd " + hwnd.ToInt64() + ": " + ex.Message); }
            if (el == null) throw new Exception("hwnd " + hwnd.ToInt64() + " does not expose UIA");
            return el;
        }

        private static string DoList(IntPtr hwnd, int max)
        {
            AutomationElement root = Root(hwnd);
            string rootName = "";
            try { rootName = root.Current.Name; } catch { }

            AutomationElementCollection all;
            try
            {
                all = root.FindAll(TreeScope.Descendants, Condition.TrueCondition);
            }
            catch (Exception ex)
            {
                return "{\"ok\":false,\"error\":" + J.S("FindAll failed: " + ex.Message) + "}";
            }

            StringBuilder items = new StringBuilder(4096);
            int count = 0;
            int total = all.Count;
            for (int i = 0; i < total; i++)
            {
                if (count >= max) break;
                AutomationElement el = all[i];
                string pats = "";
                object o;
                if (el.TryGetCurrentPattern(InvokePattern.Pattern, out o)) { pats += "invoke "; o = null; }
                if (el.TryGetCurrentPattern(ValuePattern.Pattern, out o)) { pats += "value "; o = null; }
                if (el.TryGetCurrentPattern(SelectionItemPattern.Pattern, out o)) { pats += "select "; o = null; }
                if (el.TryGetCurrentPattern(ExpandCollapsePattern.Pattern, out o)) { pats += "expand "; o = null; }
                if (pats.Length == 0) continue;

                AutomationElement.AutomationElementInformation cur;
                try { cur = el.Current; } catch { continue; }

                bool isSel = false;
                if (pats.IndexOf("select", StringComparison.Ordinal) >= 0)
                {
                    object so;
                    if (el.TryGetCurrentPattern(SelectionItemPattern.Pattern, out so))
                    {
                        try { isSel = ((SelectionItemPattern)so).Current.IsSelected; } catch { }
                    }
                }
                System.Windows.Rect r = System.Windows.Rect.Empty;
                try { r = cur.BoundingRectangle; } catch { }

                if (count > 0) items.Append(',');
                items.Append('{');
                items.Append("\"idx\":").Append(J.N(count)).Append(',');
                items.Append("\"name\":").Append(J.S(cur.Name)).Append(',');
                items.Append("\"type\":").Append(J.S(StripCtrl(cur.ControlType.ProgrammaticName))).Append(',');
                items.Append("\"patterns\":").Append(J.S(pats.Trim())).Append(',');
                items.Append("\"offscreen\":").Append(J.B(cur.IsOffscreen)).Append(',');
                items.Append("\"enabled\":").Append(J.B(cur.IsEnabled)).Append(',');
                items.Append("\"selected\":").Append(J.B(isSel)).Append(',');
                items.Append("\"rect\":{\"x\":").Append(J.N((long)r.X))
                     .Append(",\"y\":").Append(J.N((long)r.Y))
                     .Append(",\"w\":").Append(J.N((long)r.Width))
                     .Append(",\"h\":").Append(J.N((long)r.Height)).Append('}');
                items.Append('}');
                count++;
            }

            StringBuilder sb = new StringBuilder(4096 + items.Length);
            sb.Append('{');
            sb.Append("\"ok\":true,");
            sb.Append("\"sub\":\"list\",");
            sb.Append("\"hwnd\":").Append(J.N(hwnd.ToInt64())).Append(',');
            sb.Append("\"windowName\":").Append(J.S(rootName)).Append(',');
            sb.Append("\"totalElements\":").Append(J.N(total)).Append(',');
            sb.Append("\"operableCount\":").Append(J.N(count)).Append(',');
            sb.Append("\"truncated\":").Append(J.B(count >= max)).Append(',');
            sb.Append("\"items\":[").Append(items).Append(']');
            sb.Append('}');
            return sb.ToString();
        }

        private static string StripCtrl(string s)
        {
            if (s == null) return "";
            if (s.StartsWith("ControlType.", StringComparison.Ordinal)) return s.Substring(12);
            return s;
        }

        private static string DoForeground()
        {
            IntPtr fg = GetForegroundWindow();
            StringBuilder sb = new StringBuilder(256);
            sb.Append('{');
            sb.Append("\"ok\":true,\"sub\":\"fg\",");
            sb.Append("\"foregroundHwnd\":").Append(J.N(fg.ToInt64())).Append(',');
            sb.Append("\"foregroundTitle\":").Append(J.S(WinText(fg))).Append(',');
            sb.Append("\"foregroundClass\":").Append(J.S(WinClass(fg))).Append(',');
            sb.Append("\"foregroundPid\":").Append(J.N(WinPid(fg)));
            sb.Append('}');
            return sb.ToString();
        }

        private static string DoRestore(IntPtr target)
        {
            IntPtr fg0 = GetForegroundWindow();
            if (target == IntPtr.Zero || !IsWindow(target))
            {
                return "{\"ok\":false,\"error\":" + J.S("restore target is not a window") + "}";
            }
            bool ok = SetForegroundWindow(target);
            Thread.Sleep(60);
            IntPtr fg1 = GetForegroundWindow();
            StringBuilder sb = new StringBuilder(256);
            sb.Append('{');
            sb.Append("\"ok\":").Append(J.B(fg1 == target)).Append(',');
            sb.Append("\"sub\":\"restore\",");
            sb.Append("\"apiOk\":").Append(J.B(ok)).Append(',');
            sb.Append("\"beforeHwnd\":").Append(J.N(fg0.ToInt64())).Append(',');
            sb.Append("\"targetHwnd\":").Append(J.N(target.ToInt64())).Append(',');
            sb.Append("\"afterHwnd\":").Append(J.N(fg1.ToInt64())).Append(',');
            sb.Append("\"restored\":").Append(J.B(fg1 == target));
            sb.Append('}');
            return sb.ToString();
        }

        private static string DoAction(string sub, IntPtr hwnd, string needle, string text, bool wantRestore, bool force)
        {
            if (needle.Length == 0) throw new Exception("name (the search substring) is empty");

            AutomationElement root = Root(hwnd);
            AutomationPattern want;
            if (sub == "setvalue") want = ValuePattern.Pattern;
            else if (sub == "select") want = SelectionItemPattern.Pattern;
            else want = InvokePattern.Pattern;

            AutomationElementCollection all = root.FindAll(TreeScope.Descendants, Condition.TrueCondition);
            int total = all.Count;
            string needleLower = needle.ToLowerInvariant();
            AutomationElement target = null;
            string matchedName = "";
            int matchedIdx = -1;
            int scanned = 0;

            for (int i = 0; i < total; i++)
            {
                AutomationElement el = all[i];
                scanned++;
                string nm;
                try { nm = el.Current.Name; } catch { continue; }
                if (string.IsNullOrEmpty(nm)) continue;
                if (nm.ToLowerInvariant().IndexOf(needleLower, StringComparison.Ordinal) < 0) continue;
                object o;
                if (el.TryGetCurrentPattern(want, out o)) { target = el; matchedName = nm; matchedIdx = i; break; }
            }

            // ★ 2026-10-26 的事故驱动这段保护：ValuePattern.SetValue 是**整体替换**，不是插入。
            // 我在没有核对目标身份的情况下，对一个正在编辑的 38KB 文档执行了 setvalue，
            // 内容被替换成 15 个字符 —— 证据是记事本恢复存档从 27657 字节塌成 52 字节。
            // ⇒ setvalue 默认 fail-closed：目标已有内容且新值更短 ⇒ 拒绝，除非显式 force=1。
            int prevLen = -1;
            bool wouldDestroy = false;
            if (sub == "setvalue" && target != null)
            {
                object vpPrev;
                if (target.TryGetCurrentPattern(ValuePattern.Pattern, out vpPrev))
                {
                    try
                    {
                        string cur = ((ValuePattern)vpPrev).Current.Value;
                        prevLen = (cur == null) ? 0 : cur.Length;
                        wouldDestroy = (prevLen > 0) && (text.Length < prevLen);
                    }
                    catch { }
                }
            }
            bool refused = (sub == "setvalue") && wouldDestroy && !force;

            IntPtr fgBefore = GetForegroundWindow();
            IntPtr fgDuring = IntPtr.Zero;
            IntPtr fgAfterAction = IntPtr.Zero;
            IntPtr fgAfterRestore = IntPtr.Zero;
            bool acted = false;
            bool restoreTried = false;
            bool restoreApiOk = false;
            string actErr = "";

            if (target == null)
            {
                actErr = "no element whose name contains \"" + needle + "\" supports " + sub
                         + " (scanned " + scanned + "/" + total + ")";
            }
            else if (refused)
            {
                actErr = "REFUSED: setvalue REPLACES the whole value. The target currently holds "
                         + prevLen + " chars; the new text is only " + text.Length
                         + " chars. Nothing was written. Pass force=1 only if replacing is intended.";
            }
            else
            {
                try
                {
                    object p;
                    if (!target.TryGetCurrentPattern(want, out p)) throw new Exception("pattern vanished between probe and execute");
                    if (sub == "setvalue") { ((ValuePattern)p).SetValue(text); }
                    else if (sub == "select") { ((SelectionItemPattern)p).Select(); }
                    else { ((InvokePattern)p).Invoke(); }
                    acted = true;
                    Thread.Sleep(180);
                    fgDuring = GetForegroundWindow();
                }
                catch (Exception ex)
                {
                    actErr = ex.GetType().Name + ": " + ex.Message;
                    fgDuring = GetForegroundWindow();
                }
            }

            fgAfterAction = GetForegroundWindow();

            if (acted && wantRestore && fgAfterAction != fgBefore && fgBefore != IntPtr.Zero && IsWindow(fgBefore))
            {
                restoreTried = true;
                try { restoreApiOk = SetForegroundWindow(fgBefore); } catch { }
                Thread.Sleep(80);
                fgAfterRestore = GetForegroundWindow();
            }
            else
            {
                fgAfterRestore = fgAfterAction;
            }

            StringBuilder sb = new StringBuilder(1024);
            sb.Append('{');
            sb.Append("\"ok\":").Append(J.B(acted)).Append(',');
            sb.Append("\"sub\":").Append(J.S(sub)).Append(',');
            sb.Append("\"hwnd\":").Append(J.N(hwnd.ToInt64())).Append(',');
            if (actErr.Length > 0) sb.Append("\"error\":").Append(J.S(actErr)).Append(',');
            sb.Append("\"matched\":").Append(J.S(matchedName)).Append(',');
            sb.Append("\"matchedIndex\":").Append(J.N(matchedIdx)).Append(',');
            // Identity of the thing we just touched. The caller MUST be able to check that
            // this is the window it meant - "hwnd 29362906" alone told me nothing.
            sb.Append("\"targetWindowTitle\":").Append(J.S(WinText(hwnd))).Append(',');
            sb.Append("\"targetProcess\":").Append(J.S(ProcNameOf(hwnd))).Append(',');
            sb.Append("\"previousValueLength\":").Append(J.N(prevLen)).Append(',');
            sb.Append("\"newValueLength\":").Append(J.N(sub == "setvalue" ? text.Length : 0)).Append(',');
            sb.Append("\"wouldDestroy\":").Append(J.B(wouldDestroy)).Append(',');
            sb.Append("\"refused\":").Append(J.B(refused)).Append(',');
            sb.Append("\"scanned\":").Append(J.N(scanned)).Append(',');
            sb.Append("\"totalElements\":").Append(J.N(total)).Append(',');
            sb.Append("\"foregroundBefore\":").Append(J.N(fgBefore.ToInt64())).Append(',');
            sb.Append("\"foregroundDuring\":").Append(J.N(fgDuring.ToInt64())).Append(',');
            sb.Append("\"foregroundAfterAction\":").Append(J.N(fgAfterAction.ToInt64())).Append(',');
            sb.Append("\"foregroundAfterRestore\":").Append(J.N(fgAfterRestore.ToInt64())).Append(',');
            sb.Append("\"stolenByAction\":").Append(J.B(acted && fgAfterAction != fgBefore)).Append(',');
            sb.Append("\"restoreTried\":").Append(J.B(restoreTried)).Append(',');
            sb.Append("\"restoreApiOk\":").Append(J.B(restoreApiOk)).Append(',');
            // The headline criterion: after everything settles, is the user's
            // foreground exactly the window it was before we touched anything?
            sb.Append("\"foregroundUnchanged\":").Append(J.B(fgAfterRestore == fgBefore)).Append(',');
            sb.Append("\"uiAccess\":").Append(J.N(ReadUIAccess()));
            sb.Append('}');
            return sb.ToString();
        }
    }
}
