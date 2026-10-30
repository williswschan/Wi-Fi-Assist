#Requires -Version 5.1

Param(
    [Switch]$StaHost
)

$ErrorActionPreference = "Stop"
$Script:IsClosing = $False
$Script:ExitCode = 0
$Script:LastLoggedLinkState = ""
$TempFolder = $Env:TEMP
If ([String]::IsNullOrWhiteSpace($TempFolder)) {
    $TempFolder = [System.IO.Path]::GetTempPath()
}
$Script:LogPath = Join-Path $TempFolder "WiFiAssist.log"

# This logger can also run on CLR worker threads, where a PowerShell script
# block has no runspace. All writers use the same bounded, per-log mutex.
$DiagnosticsSource = @'
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

public static class SignInDiagnostics
{
    public const long MaxBytes = 1024 * 1024;
    public const int Archives = 3;
    private static readonly object Gate = new object();
    private static readonly Encoding Utf8 = new UTF8Encoding(false);
    private static string LogPath;
    private static string MutexName;
    private static bool Listening;

    public static void Configure(string path)
    {
        lock (Gate)
        {
            LogPath = Path.GetFullPath(path);
            using (SHA256 hash = SHA256.Create())
                MutexName = "Local\\WiFiAssist.Log." + BitConverter.ToString(
                    hash.ComputeHash(Utf8.GetBytes(LogPath.ToUpperInvariant()))).Replace("-", "");
        }
    }

    public static void Start()
    {
        lock (Gate)
        {
            if (Listening) return;
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
            Listening = true;
        }
    }

    public static void Stop()
    {
        lock (Gate)
        {
            if (!Listening) return;
            AppDomain.CurrentDomain.UnhandledException -= OnUnhandledException;
            Listening = false;
        }
    }

    private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs args)
    {
        WriteException("Process unhandled exception; terminating=" + args.IsTerminating,
            args.ExceptionObject as Exception);
    }

    public static void WriteException(string operation, Exception error)
    {
        // Exception messages can contain paths, SSIDs or URLs. Record stable
        // error types/codes instead; never serialize authentication data.
        string detail = error == null ? "Unknown exception" :
            error.GetType().FullName + "; HResult=0x" + error.HResult.ToString("X8");
        if (error != null && error.InnerException != null)
            detail += "; inner=" + error.InnerException.GetType().FullName +
                "; innerHResult=0x" + error.InnerException.HResult.ToString("X8");
        Write("[ERROR] " + operation + ": " + detail);
    }

    public static void Write(string message)
    {
        try
        {
            lock (Gate)
            {
                if (LogPath == null || MutexName == null) return;
                string safe = (message ?? "").Replace('\r', ' ').Replace('\n', ' ');
                if (safe.Length > 2048) safe = safe.Substring(0, 2048);
                byte[] line = Utf8.GetBytes("[" + DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss.fff zzz") +
                    "] " + safe + Environment.NewLine);
                using (Mutex mutex = new Mutex(false, MutexName))
                {
                    bool acquired = false;
                    try
                    {
                        try { acquired = mutex.WaitOne(100); }
                        catch (AbandonedMutexException) { acquired = true; }
                        if (!acquired) return;
                        if (File.Exists(LogPath) && new FileInfo(LogPath).Length + line.Length > MaxBytes)
                        {
                            // Refuse rotation while another writer holds the active
                            // file. Keep this guard open through the rename.
                            using (FileStream guard = new FileStream(LogPath, FileMode.Open,
                                FileAccess.Read, FileShare.Read | FileShare.Delete))
                            {
                                string oldest = LogPath + "." + Archives;
                                if (File.Exists(oldest)) File.Delete(oldest);
                                for (int index = Archives - 1; index >= 1; index--)
                                {
                                    string source = LogPath + "." + index;
                                    if (File.Exists(source)) File.Move(source, LogPath + "." + (index + 1));
                                }
                                File.Move(LogPath, LogPath + ".1");
                            }
                        }
                        using (FileStream stream = new FileStream(LogPath, FileMode.Append,
                            FileAccess.Write, FileShare.Read)) stream.Write(line, 0, line.Length);
                    }
                    finally { if (acquired) mutex.ReleaseMutex(); }
                }
            }
        }
        catch (Exception) { /* Diagnostics must not break the application. */ }
    }
}
'@

If ($Null -Eq ([System.Management.Automation.PSTypeName]"SignInDiagnostics").Type) {
    Add-Type -TypeDefinition $DiagnosticsSource -Language CSharp
}
Try { [SignInDiagnostics]::Configure($Script:LogPath) }
Catch { Write-Warning "Wi-Fi Assist could not initialise its diagnostic log." }
[SignInDiagnostics]::Start()

Function Write-SignInLog {
    Param(
        [String]$Message
    )

    [SignInDiagnostics]::Write($Message)
}

Function Write-SignInError {
    Param([String]$Operation, [System.Exception]$Exception)
    [SignInDiagnostics]::WriteException($Operation, $Exception)
}

If ([String]::IsNullOrWhiteSpace($PSCommandPath)) {
    Write-SignInLog "[ERROR] Run this script from a file path."
    Write-Error "[ERROR] Run this script from a file path."
    Exit 1
}

$IsDesktopHost = $PSVersionTable.PSEdition -Eq "Desktop"
$IsStaThread = [System.Threading.Thread]::CurrentThread.ApartmentState -Eq [System.Threading.ApartmentState]::STA
If (($IsDesktopHost -Eq $False) -Or ($IsStaThread -Eq $False)) {
    If ($StaHost -Eq $True) {
        Write-SignInLog "[ERROR] WPF requires Windows PowerShell 5.1 running in STA mode."
        Write-Error "[ERROR] WPF requires Windows PowerShell 5.1 running in STA mode."
        Exit 1
    }

    Write-SignInLog "[INFO] Restarting in Windows PowerShell STA. This process will exit."
    Write-Host "[INFO] Restarting in Windows PowerShell STA so WPF can open the window."
    $WindowsPowerShell = Join-Path $Env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $ArgumentList = @(
        "-NoProfile",
        "-STA",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        ('"' + $PSCommandPath + '"'),
        "-StaHost"
    )
    Try {
        Start-Process -FilePath $WindowsPowerShell -ArgumentList $ArgumentList -WindowStyle Hidden -ErrorAction Stop | Out-Null
    }
    Catch {
        Write-SignInError -Operation "Windows PowerShell relaunch failed" -Exception $_.Exception
        Write-Error "Wi-Fi Assist could not start Windows PowerShell. See the diagnostic log."
        Exit 1
    }
    Exit 0
}

Write-SignInLog ("[INFO] Sign-in script started. PID=" + $PID + ". ErrorAction=Stop.")

Try {
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$WifiMonitorSource = @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

public sealed class WifiSnapshot
{
    public WifiSnapshot(string state, string detail)
    {
        State = state;
        Detail = detail;
    }

    public string State { get; private set; }
    public string Detail { get; private set; }
    public int DiagnosticCode { get; internal set; }
}

public static class WifiMonitor
{
    private static int LastNativeError;
    private const int ErrorSuccess = 0;
    private const int ErrorServiceNotActive = 1062;
    private const int ErrorAccessDenied = 5;
    private const uint ClientVersion = 2;
    private const int RadioStateOff = 2;
    private const int SsidLengthOffset = 520;
    private const int ProfileNameOffset = 8;
    private const int InterfaceStateOffset = 528;
    private const int InterfaceStride = 532;

    public static WifiSnapshot Query()
    {
        LastNativeError = 0;
        try
        {
            WifiSnapshot snapshot = QueryCore();
            snapshot.DiagnosticCode = LastNativeError;
            return snapshot;
        }
        catch (Exception error)
        {
            return new WifiSnapshot("Unavailable", "Could not read Wi-Fi status.") { DiagnosticCode = error.HResult };
        }
    }

    private static WifiSnapshot QueryCore()
    {
        uint negotiatedVersion;
        IntPtr handle;
        int openResult = NativeMethods.WlanOpenHandle(ClientVersion, IntPtr.Zero, out negotiatedVersion, out handle);
        if (openResult != ErrorSuccess)
        {
            LastNativeError = openResult;
            return new WifiSnapshot("Unavailable", DescribeApiError(openResult));
        }

        try
        {
            IntPtr listPointer;
            int enumResult = NativeMethods.WlanEnumInterfaces(handle, IntPtr.Zero, out listPointer);
            if (enumResult != ErrorSuccess)
            {
                LastNativeError = enumResult;
                return new WifiSnapshot("Unavailable", DescribeApiError(enumResult));
            }

            if (listPointer == IntPtr.Zero)
            {
                return new WifiSnapshot("NoAdapter", "A wireless adapter was not found.");
            }

            try
            {
                int count = Marshal.ReadInt32(listPointer);
                if (count <= 0)
                {
                    return new WifiSnapshot("NoAdapter", "A wireless adapter was not found.");
                }

                List<string> connectedNames = new List<string>();
                List<Guid> connectedInterfaces = new List<Guid>();
                bool anyConnecting = false;
                bool anyRadioOn = false;
                bool anyRadioOff = false;
                bool radioStateKnown = false;

                for (int index = 0; index < count; index++)
                {
                    IntPtr item = IntPtr.Add(listPointer, 8 + (index * InterfaceStride));
                    Guid interfaceGuid = (Guid)Marshal.PtrToStructure(item, typeof(Guid));
                    int state = Marshal.ReadInt32(item, InterfaceStateOffset);

                    if (state == 1)
                    {
                        connectedInterfaces.Add(interfaceGuid);
                        connectedNames.Add(QueryConnectedName(handle, interfaceGuid));
                        continue;
                    }

                    if (state == 5 || state == 6 || state == 7)
                    {
                        anyConnecting = true;
                        continue;
                    }

                    bool radioOff;
                    if (TryQueryRadioOff(handle, interfaceGuid, out radioOff))
                    {
                        radioStateKnown = true;
                        if (radioOff)
                        {
                            anyRadioOff = true;
                        }
                        else
                        {
                            anyRadioOn = true;
                        }
                    }
                }

                if (connectedInterfaces.Count > 0)
                {
                    string names = JoinNetworkNames(connectedNames);
                    if (!HasUsableAddress(connectedInterfaces))
                    {
                        if (names.StartsWith("Network: "))
                        {
                            return new WifiSnapshot("Connecting", names);
                        }

                        return new WifiSnapshot("Connecting", "Waiting for an address from the network.");
                    }

                    return new WifiSnapshot("Connected", names);
                }

                if (anyConnecting)
                {
                    return new WifiSnapshot("Connecting", "Connecting to the Wi-Fi network.");
                }

                if (radioStateKnown && anyRadioOff && !anyRadioOn)
                {
                    return new WifiSnapshot("RadioOff", "The Wi-Fi radio is turned off.");
                }

                return new WifiSnapshot("Disconnected", "No Wi-Fi network is associated.");
            }
            finally
            {
                NativeMethods.WlanFreeMemory(listPointer);
            }
        }
        finally
        {
            NativeMethods.WlanCloseHandle(handle, IntPtr.Zero);
        }
    }

    private static string JoinNetworkNames(List<string> connectedNames)
    {
        List<string> visible = new List<string>();
        bool sawHiddenName = false;
        foreach (string name in connectedNames)
        {
            if (name == null)
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(name))
            {
                sawHiddenName = true;
                continue;
            }

            visible.Add(name);
        }

        if (visible.Count > 0)
        {
            return "Network: " + string.Join(", ", visible.ToArray());
        }

        if (sawHiddenName)
        {
            return "Connected. The network name is hidden.";
        }

        return "Connected. The network name could not be read.";
    }

    private static bool HasUsableAddress(List<Guid> interfaceGuids)
    {
        try
        {
            NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
            for (int index = 0; index < interfaceGuids.Count; index++)
            {
                string withBraces = interfaceGuids[index].ToString("B");
                string plain = interfaceGuids[index].ToString("D");
                for (int adapterIndex = 0; adapterIndex < adapters.Length; adapterIndex++)
                {
                    NetworkInterface adapter = adapters[adapterIndex];
                    if (adapter.NetworkInterfaceType != NetworkInterfaceType.Wireless80211)
                    {
                        continue;
                    }

                    if (adapter.OperationalStatus != OperationalStatus.Up)
                    {
                        continue;
                    }

                    if (!string.Equals(adapter.Id, withBraces, StringComparison.OrdinalIgnoreCase)
                        && !string.Equals(adapter.Id, plain, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    foreach (UnicastIPAddressInformation address in adapter.GetIPProperties().UnicastAddresses)
                    {
                        if (IsUsableAddress(address.Address))
                        {
                            return true;
                        }
                    }
                }
            }
        }
        catch (Exception)
        {
            return false;
        }

        return false;
    }

    private static bool IsUsableAddress(IPAddress address)
    {
        if (address == null || IPAddress.IsLoopback(address))
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] bytes = address.GetAddressBytes();
            if (bytes.Length != 4 || bytes[0] == 0 || bytes[0] >= 224)
            {
                return false;
            }

            if (bytes[0] == 169 && bytes[1] == 254)
            {
                return false;
            }

            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return !address.Equals(IPAddress.IPv6Any) && !address.IsIPv6LinkLocal && !address.IsIPv6Multicast;
        }

        return false;
    }

    private static string QueryConnectedName(IntPtr handle, Guid interfaceGuid)
    {
        Guid guid = interfaceGuid;
        uint dataSize;
        IntPtr data;
        int result = NativeMethods.WlanQueryInterface(
            handle,
            ref guid,
            7,
            IntPtr.Zero,
            out dataSize,
            out data,
            IntPtr.Zero);

        if (result != ErrorSuccess || data == IntPtr.Zero)
        {
            LastNativeError = result;
            return null;
        }

        try
        {
            string ssid = ReadSsid(data, dataSize);
            if (!string.IsNullOrWhiteSpace(ssid))
            {
                return ssid;
            }

            return ReadProfileName(data, dataSize);
        }
        finally
        {
            NativeMethods.WlanFreeMemory(data);
        }
    }

    private static bool TryQueryRadioOff(IntPtr handle, Guid interfaceGuid, out bool radioOff)
    {
        radioOff = false;
        Guid guid = interfaceGuid;
        uint dataSize;
        IntPtr data;
        int result = NativeMethods.WlanQueryInterface(
            handle,
            ref guid,
            4,
            IntPtr.Zero,
            out dataSize,
            out data,
            IntPtr.Zero);

        if (result != ErrorSuccess || data == IntPtr.Zero)
        {
            LastNativeError = result;
            return false;
        }

        try
        {
            if (dataSize < 16)
            {
                return false;
            }

            int phyCount = Marshal.ReadInt32(data);
            if (phyCount <= 0)
            {
                return false;
            }

            if (phyCount > 64)
            {
                phyCount = 64;
            }

            bool sawPhy = false;
            bool anyOff = false;
            for (int index = 0; index < phyCount; index++)
            {
                int phyOffset = 4 + (index * 12);
                if (dataSize < (uint)(phyOffset + 12))
                {
                    break;
                }

                int software = Marshal.ReadInt32(data, phyOffset + 4);
                int hardware = Marshal.ReadInt32(data, phyOffset + 8);
                sawPhy = true;
                if (software == RadioStateOff || hardware == RadioStateOff)
                {
                    anyOff = true;
                }
            }

            if (!sawPhy)
            {
                return false;
            }

            radioOff = anyOff;
            return true;
        }
        finally
        {
            NativeMethods.WlanFreeMemory(data);
        }
    }

    private static string ReadSsid(IntPtr data, uint dataSize)
    {
        if (dataSize < SsidLengthOffset + 4)
        {
            return "";
        }

        int length = Marshal.ReadInt32(data, SsidLengthOffset);
        if (length <= 0)
        {
            return "";
        }

        if (length > 32)
        {
            length = 32;
        }

        if (dataSize < SsidLengthOffset + 4 + length)
        {
            return "";
        }

        byte[] bytes = new byte[length];
        Marshal.Copy(IntPtr.Add(data, SsidLengthOffset + 4), bytes, 0, length);
        return Encoding.UTF8.GetString(bytes).Trim('\0', ' ');
    }

    private static string ReadProfileName(IntPtr data, uint dataSize)
    {
        if (dataSize < ProfileNameOffset + 512)
        {
            return "";
        }

        string name = Marshal.PtrToStringUni(IntPtr.Add(data, ProfileNameOffset), 256) ?? "";
        int terminator = name.IndexOf('\0');
        if (terminator >= 0)
        {
            name = name.Substring(0, terminator);
        }

        return name.Trim();
    }

    private static string DescribeApiError(int errorCode)
    {
        if (errorCode == ErrorServiceNotActive)
        {
            return "The WLAN AutoConfig service is not running.";
        }

        if (errorCode == ErrorAccessDenied)
        {
            return "Access was denied while reading Wi-Fi status.";
        }

        return "Could not read Wi-Fi status (error " + errorCode + ").";
    }

    private static class NativeMethods
    {
        [DllImport("wlanapi.dll")]
        internal static extern int WlanOpenHandle(
            uint clientVersion,
            IntPtr reserved,
            out uint negotiatedVersion,
            out IntPtr clientHandle);

        [DllImport("wlanapi.dll")]
        internal static extern int WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

        [DllImport("wlanapi.dll")]
        internal static extern int WlanEnumInterfaces(
            IntPtr clientHandle,
            IntPtr reserved,
            out IntPtr interfaceList);

        [DllImport("wlanapi.dll")]
        internal static extern int WlanQueryInterface(
            IntPtr clientHandle,
            ref Guid interfaceGuid,
            int opCode,
            IntPtr reserved,
            out uint dataSize,
            out IntPtr data,
            IntPtr opcodeValueType);

        [DllImport("wlanapi.dll")]
        internal static extern void WlanFreeMemory(IntPtr memory);
    }
}
'@

If ($Null -Eq ([System.Management.Automation.PSTypeName]"WifiMonitor").Type) {
    Add-Type -TypeDefinition $WifiMonitorSource -Language CSharp
}

$CiscoBrowserSource = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

// No built-in titles/classes: identifiers must be measured and approved for
// the deployed Cisco build. Exact executable hashes also pin that build.
public sealed class CiscoWindowRule
{
    public string Action { get; set; }
    public string ExecutablePath { get; set; }
    public string Sha256 { get; set; }
    public string WindowClass { get; set; }
    public string WindowTitle { get; set; }
}

public sealed class CiscoWindowTarget
{
    public IntPtr Handle { get; set; }
    public int ProcessId { get; set; }
    public long ProcessStarted { get; set; }
    public CiscoWindowRule Rule { get; set; }
}

public static class CiscoWindowSafety
{
    public static CiscoWindowRule[] Rules = new CiscoWindowRule[0];
    public static int LastError { get; private set; }
    private static readonly Dictionary<string, string> Hashes = new Dictionary<string, string>();

    public static bool Matches(CiscoWindowRule rule, string action, string path,
        string hash, string windowClass, string title)
    {
        return rule != null && !string.IsNullOrWhiteSpace(rule.ExecutablePath) &&
            !string.IsNullOrWhiteSpace(rule.Sha256) && !string.IsNullOrWhiteSpace(rule.WindowClass) &&
            !string.IsNullOrWhiteSpace(rule.WindowTitle) &&
            string.Equals(rule.Action, action, StringComparison.Ordinal) &&
            string.Equals(rule.ExecutablePath, path, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(rule.Sha256, hash, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(rule.WindowClass, windowClass, StringComparison.Ordinal) &&
            string.Equals(rule.WindowTitle, title, StringComparison.Ordinal);
    }

    public static bool IsCandidateProcess(string action, string processName)
    {
        if (action == "CloseBrowser")
            return string.Equals(processName, "acwebhelper", StringComparison.OrdinalIgnoreCase);
        return action == "DismissNotice" &&
            (string.Equals(processName, "vpnui", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(processName, "csc_ui", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(processName, "acwebhelper", StringComparison.OrdinalIgnoreCase));
    }

    private static string ReadHash(string path, long started)
    {
        FileInfo info = new FileInfo(path);
        if (!info.Exists || info.Length > 64 * 1024 * 1024) return "";
        string key = path + "|" + started + "|" + info.Length + "|" + info.LastWriteTimeUtc.Ticks;
        string value;
        if (Hashes.TryGetValue(key, out value)) return value;
        using (SHA256 hash = SHA256.Create())
        using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            value = BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "");
        if (Hashes.Count >= 32) Hashes.Clear();
        Hashes[key] = value;
        return value;
    }

    public static List<CiscoWindowTarget> Find(string action, out int unverified)
    {
        LastError = 0;
        List<CiscoWindowTarget> approved = new List<CiscoWindowTarget>();
        HashSet<int> candidates = new HashSet<int>();
        string[] names = action == "CloseBrowser" ? new string[] { "acwebhelper" } :
            new string[] { "acwebhelper", "vpnui", "csc_ui" };
        foreach (string name in names)
        {
            foreach (Process process in Process.GetProcessesByName(name))
            {
                using (process)
                {
                    try { candidates.Add(process.Id); }
                    catch (InvalidOperationException) { }
                }
            }
        }
        int skipped = 0;
        bool enumerated = EnumWindows(delegate(IntPtr handle, IntPtr unused)
        {
            if (!IsWindowVisible(handle)) return true;
            uint pid;
            GetWindowThreadProcessId(handle, out pid);
            if (!candidates.Contains((int)pid)) return true;
            try
            {
                using (Process process = Process.GetProcessById((int)pid))
                {
                    if (!IsCandidateProcess(action, process.ProcessName)) return true;
                    skipped++;
                    // Avoid opening protected processes or hashing executables unless a
                    // rule for this operation exists.
                    bool hasRule = Array.Exists(Rules, rule => rule.Action == action);
                    if (!hasRule) return true;
                    string path = process.MainModule.FileName;
                    long started = process.StartTime.ToUniversalTime().Ticks;
                    string windowClass = ReadClass(handle);
                    string title = ReadText(handle);
                    foreach (CiscoWindowRule rule in Rules)
                    {
                        if (rule.Action != action ||
                            !string.Equals(rule.ExecutablePath, path, StringComparison.OrdinalIgnoreCase) ||
                            rule.WindowClass != windowClass || rule.WindowTitle != title) continue;
                        if (Matches(rule, action, path, ReadHash(path, started), windowClass, title))
                        {
                            approved.Add(new CiscoWindowTarget { Handle = handle, ProcessId = (int)pid,
                                ProcessStarted = started, Rule = rule });
                            skipped--;
                            break;
                        }
                    }
                }
            }
            catch (ArgumentException) { /* Process exited during enumeration. */ }
            catch (InvalidOperationException) { LastError = 6; }
            catch (System.ComponentModel.Win32Exception ex) { LastError = ex.NativeErrorCode; }
            catch (Exception ex) { LastError = ex.HResult; }
            return true;
        }, IntPtr.Zero);
        if (!enumerated) LastError = Marshal.GetLastWin32Error();
        unverified = skipped;
        return approved;
    }

    public static bool StillSameWindow(CiscoWindowTarget target)
    {
        return Presence(target) == 1;
    }

    // 0 = gone/replaced/hidden, 1 = the original visible window, -1 = unknown.
    public static int Presence(CiscoWindowTarget target)
    {
        if (target == null || !IsWindow(target.Handle) || !IsWindowVisible(target.Handle)) return 0;
        uint pid;
        GetWindowThreadProcessId(target.Handle, out pid);
        if ((int)pid != target.ProcessId) return 0;
        try
        {
            using (Process process = Process.GetProcessById(target.ProcessId))
                return process.StartTime.ToUniversalTime().Ticks == target.ProcessStarted ? 1 : 0;
        }
        catch (ArgumentException) { return 0; }
        catch (Exception error) { LastError = error.HResult; return -1; }
    }

    public static bool Revalidate(CiscoWindowTarget target)
    {
        if (!StillSameWindow(target) || !IsWindowVisible(target.Handle)) return false;
        try
        {
            using (Process process = Process.GetProcessById(target.ProcessId))
            {
                string path = process.MainModule.FileName;
                return Matches(target.Rule, target.Rule.Action, path,
                    ReadHash(path, target.ProcessStarted), ReadClass(target.Handle), ReadText(target.Handle));
            }
        }
        catch (Exception) { return false; }
    }

    public static bool RequestClose(CiscoWindowTarget target, Stopwatch clock)
    {
        LastError = 0;
        if (!Revalidate(target)) return false;
        if (clock == null || clock.ElapsedMilliseconds >= 2000) { LastError = 1460; return false; }
        if (PostMessage(target.Handle, 0x0010, IntPtr.Zero, IntPtr.Zero)) return true;
        LastError = Marshal.GetLastWin32Error();
        return false;
    }

    public static string ReadText(IntPtr handle)
    {
        StringBuilder text = new StringBuilder(2048);
        GetWindowText(handle, text, text.Capacity);
        return text.ToString();
    }

    public static string ReadClass(IntPtr handle)
    {
        StringBuilder text = new StringBuilder(256);
        GetClassName(handle, text, text.Capacity);
        return text.ToString();
    }

    public static bool Visible(IntPtr handle) { return IsWindowVisible(handle); }

    public static IntPtr FindNoticeButton(IntPtr dialog)
    {
        bool marker = false;
        List<IntPtr> buttons = new List<IntPtr>();
        EnumChildWindows(dialog, delegate(IntPtr child, IntPtr unused)
        {
            if (!IsWindowVisible(child)) return true;
            string text = ReadText(child);
            if (text.IndexOf("retry logging on with the service provider", StringComparison.OrdinalIgnoreCase) >= 0)
                marker = true;
            if (ReadClass(child) == "Button" && IsWindowEnabled(child) &&
                string.Equals(text.Replace("&", "").Trim(), "OK", StringComparison.OrdinalIgnoreCase))
                buttons.Add(child);
            return true;
        }, IntPtr.Zero);
        return marker && buttons.Count == 1 ? buttons[0] : IntPtr.Zero;
    }

    public static bool RequestDismiss(CiscoWindowTarget target, Stopwatch clock)
    {
        LastError = 0;
        if (!Revalidate(target)) return false;
        IntPtr button = FindNoticeButton(target.Handle);
        if (button == IntPtr.Zero || !StillSameWindow(target)) return false;
        uint pid;
        GetWindowThreadProcessId(button, out pid);
        if ((int)pid != target.ProcessId || !IsChild(target.Handle, button)) return false;
        if (clock == null || clock.ElapsedMilliseconds >= 5000) { LastError = 1460; return false; }
        if (PostMessage(button, 0x00F5, IntPtr.Zero, IntPtr.Zero)) return true;
        LastError = Marshal.GetLastWin32Error();
        return false;
    }

    private delegate bool EnumWindowsProc(IntPtr handle, IntPtr lParam);
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumChildWindows(IntPtr parent, EnumWindowsProc callback, IntPtr lParam);
    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr handle, out uint processId);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindow(IntPtr handle);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr handle);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowEnabled(IntPtr handle);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsChild(IntPtr parent, IntPtr child);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr handle, StringBuilder text, int maxCount);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr handle, StringBuilder text, int maxCount);
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessage(IntPtr handle, uint message, IntPtr wParam, IntPtr lParam);
}

public static class CiscoBrowserCloser
{
    private static CiscoWindowTarget Target;
    private static bool Attempted;
    private static Stopwatch Clock;
    public static int LastError { get; private set; }
    public static void Begin() { Target = null; Attempted = false; LastError = 0; Clock = Stopwatch.StartNew(); }
    public static void Stop() { if (Clock != null) Clock.Stop(); Clock = null; Target = null; }

    // Called every 250 ms for at most two seconds. Exactly one close request
    // is allowed per operation, and only an unambiguous approved window qualifies.
    public static string Poll()
    {
        if (Clock == null) return "None";
        if (Target != null)
        {
            int presence = CiscoWindowSafety.Presence(Target);
            LastError = CiscoWindowSafety.LastError;
            if (presence == 0) return "Closed";
            if (presence < 0) return "Manual";
            return Clock.ElapsedMilliseconds >= 2000 ? "StillOpen" : "Waiting";
        }
        if (Attempted) return "Manual";
        if (Clock.ElapsedMilliseconds >= 2000) return "Manual";
        int unverified;
        List<CiscoWindowTarget> matches = CiscoWindowSafety.Find("CloseBrowser", out unverified);
        LastError = CiscoWindowSafety.LastError;
        if (matches.Count > 1) return "Manual";
        if (matches.Count == 1)
        {
            if (Clock.ElapsedMilliseconds >= 2000) return "Manual";
            Attempted = true;
            Target = matches[0];
            if (!CiscoWindowSafety.RequestClose(Target, Clock))
            {
                LastError = CiscoWindowSafety.LastError;
                Target = null;
                return "Manual";
            }
            return "Waiting";
        }
        if (unverified > 0 || LastError != 0) return "Manual";
        // With no approved rules there is nothing safe to wait for.
        bool enabled = Array.Exists(CiscoWindowSafety.Rules, rule => rule.Action == "CloseBrowser");
        return enabled && Clock.ElapsedMilliseconds < 2000 ? "Waiting" : "None";
    }
}

public static class CiscoFailoverNotice
{
    private static CiscoWindowTarget Target;
    private static bool Attempted;
    private static Stopwatch Clock;
    public static int LastError { get; private set; }
    public static void Begin() { Target = null; Attempted = false; LastError = 0; Clock = Stopwatch.StartNew(); }
    public static void Stop() { Target = null; Attempted = true; if (Clock != null) Clock.Stop(); Clock = null; }
    public static string Poll()
    {
        if (Clock == null || Clock.ElapsedMilliseconds >= 5000) return "Manual";
        if (Target != null)
        {
            int presence = CiscoWindowSafety.Presence(Target);
            LastError = CiscoWindowSafety.LastError;
            return presence == 0 ? "Dismissed" : (presence < 0 ? "Manual" : "Requested");
        }
        if (Attempted) return "Manual";
        int unverified;
        List<CiscoWindowTarget> matches = CiscoWindowSafety.Find("DismissNotice", out unverified);
        LastError = CiscoWindowSafety.LastError;
        if (matches.Count > 1) return "Manual";
        if (matches.Count == 0) return "Waiting";
        if (Clock.ElapsedMilliseconds >= 5000) return "Manual";
        Attempted = true;
        if (!CiscoWindowSafety.RequestDismiss(matches[0], Clock))
        {
            LastError = CiscoWindowSafety.LastError;
            return "Manual";
        }
        Target = matches[0];
        return "Requested";
    }
}
'@

If ($Null -Eq ([System.Management.Automation.PSTypeName]"CiscoWindowSafety").Type) {
    Add-Type -TypeDefinition $CiscoBrowserSource -Language CSharp
}

$NetworkChangeRelaySource = @'
using System;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Windows.Threading;

public static class NetworkChangeRelay
{
    private static readonly object Gate = new object();
    private static bool IsListening;
    private static bool Pending;
    private static int Generation;
    private static Dispatcher Dispatcher;
    private static Action Callback;

    public static void Start(Dispatcher dispatcher, Action callback)
    {
        Stop();
        lock (Gate)
        {
            Dispatcher = dispatcher;
            Callback = callback;
            IsListening = true;
            NetworkChange.NetworkAddressChanged += OnAddressChanged;
            NetworkChange.NetworkAvailabilityChanged += OnAvailabilityChanged;
        }
    }

    public static void Stop()
    {
        lock (Gate)
        {
            Generation++;
            if (IsListening)
            {
                NetworkChange.NetworkAddressChanged -= OnAddressChanged;
                NetworkChange.NetworkAvailabilityChanged -= OnAvailabilityChanged;
            }
            IsListening = false;
            Pending = false;
            Callback = null;
            Dispatcher = null;
        }
    }

    private static void OnAddressChanged(object sender, EventArgs args) { Dispatch(); }
    private static void OnAvailabilityChanged(object sender, NetworkAvailabilityEventArgs args) { Dispatch(); }

    private static void Dispatch()
    {
        lock (Gate)
        {
            if (!IsListening || Pending || Dispatcher == null ||
                Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished) return;
            int generation = Generation;
            Pending = true;
            try
            {
                Dispatcher.BeginInvoke(new Action(delegate()
                {
                    Action callback;
                    lock (Gate)
                    {
                        // Stop invalidates actions already queued on the dispatcher.
                        if (!IsListening || generation != Generation) return;
                        Pending = false;
                        callback = Callback;
                    }
                    if (callback != null) callback();
                }));
            }
            catch (InvalidOperationException) { Pending = false; }
        }
    }
}

// Coordinates are device pixels; the caller converts them through WPF's
// presentation source, keeping placement in the window's coordinate system.
public static class WindowWorkArea
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)]
    private struct MonitorInfo { public int Size; public Rect Monitor, Work; public uint Flags; }
    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr window, uint flags);
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfo(IntPtr monitor, ref MonitorInfo info);
    public static int[] Get(IntPtr window)
    {
        MonitorInfo info = new MonitorInfo();
        info.Size = Marshal.SizeOf(typeof(MonitorInfo));
        IntPtr monitor = MonitorFromWindow(window, 2);
        if (monitor == IntPtr.Zero || !GetMonitorInfo(monitor, ref info)) return null;
        return new int[] { info.Work.Left, info.Work.Top, info.Work.Right, info.Work.Bottom };
    }
}
'@

If ($Null -Eq ([System.Management.Automation.PSTypeName]"NetworkChangeRelay").Type) {
    Add-Type -TypeDefinition $NetworkChangeRelaySource -ReferencedAssemblies "WindowsBase" -Language CSharp
}

# Plain HTTP on a normal site. Connectivity-check hosts such as msftconnecttest.com
# are often allowed through without showing the airline sign-in page.
$Script:TriggerUrl = "http://neverssl.com"
$Script:LinkState = "Unavailable"
$Script:IsOpening = $False
$Script:SsidWarningShown = $False
$Script:LastLoggedDiagnostic = 0
$Script:AppFolder = Split-Path -Parent $PSCommandPath

Function Import-CiscoWindowRules {
    Param([String]$Path = (Join-Path $Script:AppFolder "CiscoWindowRules.json"))

    [CiscoWindowSafety]::Rules = [CiscoWindowRule[]]@()
    If (-Not (Test-Path -LiteralPath $Path)) { Return }
    Try {
        If ((Get-Item -LiteralPath $Path).Length -Gt 65536) { Throw "Rules file is too large." }
        $Settings = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        If ($Settings.SchemaVersion -Ne 1 -Or $Null -Eq $Settings.Rules -Or @($Settings.Rules).Count -Gt 16) {
            Throw "Invalid rules schema."
        }
        $Rules = New-Object 'System.Collections.Generic.List[CiscoWindowRule]'
        ForEach ($Item in @($Settings.Rules)) {
            If ($Item.Action -NotIn @("CloseBrowser", "DismissNotice") -Or
                [String]::IsNullOrWhiteSpace($Item.ExecutablePath) -Or
                $Item.ExecutablePath -NotMatch '^[a-zA-Z]:\\' -Or
                $Item.Sha256 -NotMatch '^[0-9a-fA-F]{64}$' -Or
                [String]::IsNullOrWhiteSpace($Item.WindowClass) -Or
                [String]::IsNullOrWhiteSpace($Item.WindowTitle)) { Throw "Incomplete window identity." }
            $FullPath = [IO.Path]::GetFullPath($Item.ExecutablePath)
            $Drive = New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($FullPath))
            If ($Drive.DriveType -Ne [IO.DriveType]::Fixed -Or [IO.Path]::GetExtension($FullPath) -Ne ".exe" -Or
                -Not [CiscoWindowSafety]::IsCandidateProcess($Item.Action, [IO.Path]::GetFileNameWithoutExtension($FullPath))) {
                Throw "Unsupported process for this operation."
            }
            $Rule = New-Object CiscoWindowRule
            $Rule.Action = $Item.Action
            $Rule.ExecutablePath = $FullPath
            $Rule.Sha256 = $Item.Sha256
            $Rule.WindowClass = $Item.WindowClass
            $Rule.WindowTitle = $Item.WindowTitle
            $Rules.Add($Rule)
        }
        [CiscoWindowSafety]::Rules = $Rules.ToArray()
        Write-SignInLog ("[INFO] Approved Cisco window rules loaded: " + $Rules.Count)
    }
    Catch {
        Write-SignInError -Operation "Cisco rules rejected; manual handling will be used" -Exception $_.Exception
    }
}

Import-CiscoWindowRules

Function New-FrozenBrush {
    Param(
        [Byte]$Red,
        [Byte]$Green,
        [Byte]$Blue
    )

    $Color = [System.Windows.Media.Color]::FromRgb($Red, $Green, $Blue)
    $Brush = New-Object System.Windows.Media.SolidColorBrush $Color
    $Brush.Freeze()
    Return $Brush
}

Function Show-ActionResult {
    Param(
        [String]$Message,
        [System.Windows.Media.Brush]$Foreground
    )

    If ($Script:IsClosing) { Return }
    $Script:ResultText.Text = $Message
    $Script:ResultText.Foreground = $Foreground
    $Script:ResultText.Visibility = [System.Windows.Visibility]::Visible
}

Function Get-ConnectedWifiLabel {
    $Names = New-Object System.Collections.Generic.List[String]
    Try {
        $NetworkInformation = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
        $Profiles = $NetworkInformation::GetConnectionProfiles()
        ForEach ($Profile in $Profiles) {
            $WlanDetails = $Profile.WlanConnectionProfileDetails
            If ($Null -Eq $WlanDetails) {
                Continue
            }

            $Ssid = [String]$WlanDetails.GetConnectedSsid()
            If ([String]::IsNullOrWhiteSpace($Ssid) -Eq $False) {
                $Names.Add($Ssid)
            }
        }
    }
    Catch {
        If ($Script:SsidWarningShown -Eq $False) {
            Write-SignInError -Operation "Wi-Fi network name unavailable" -Exception $_.Exception
            $Script:SsidWarningShown = $True
        }
    }

    If ($Names.Count -Eq 0) {
        Return ""
    }

    Return ("Network: " + ($Names.ToArray() -Join ", "))
}

Function Set-StepBadge {
    Param(
        [System.Windows.Controls.Border]$Badge,
        [System.Windows.Controls.TextBlock]$Mark,
        [System.Windows.Controls.TextBlock]$Title,
        [System.Windows.Media.Brush]$BadgeBrush,
        [System.Windows.Media.Brush]$MarkBrush,
        [System.Windows.Media.Brush]$TitleBrush
    )

    $Badge.Background = $BadgeBrush
    $Mark.Foreground = $MarkBrush
    $Title.Foreground = $TitleBrush
}

Function Set-NetworkButtonLabel {
    Param(
        [String]$Label
    )

    $Script:ChangeNetworkLabel.Text = $Label
    $Script:ChangeNetworkButton.Visibility = [System.Windows.Visibility]::Visible
    [System.Windows.Automation.AutomationProperties]::SetName($Script:ChangeNetworkButton, ($Label -Replace "`n", " "))
}

Function Set-WifiStatusAppearance {
    Param(
        [String]$Kind
    )

    $WhiteBrush = [System.Windows.Media.Brushes]::White
    Switch ($Kind) {
        "Connected" {
            $Script:StatusBadge.Background = $Script:ConnectedBrush
            $Script:StatusMark.Text = [String]([Char]0xE73E)
            $Script:StatusCard.Background = $Script:ConnectedCardBrush
            $Script:StatusCard.BorderBrush = $Script:ConnectedBrush
            $Script:StatusText.Foreground = $Script:SuccessTextBrush
            Set-NetworkButtonLabel -Label "Change`nNetwork"
            Set-StepBadge -Badge $Script:Step1Badge -Mark $Script:Step1Mark -Title $Script:Step1Title -BadgeBrush $Script:ConnectedBrush -MarkBrush $WhiteBrush -TitleBrush $Script:TitleBrush
            Set-StepBadge -Badge $Script:Step2Badge -Mark $Script:Step2Mark -Title $Script:Step2Title -BadgeBrush $Script:OfflineBrush -MarkBrush $WhiteBrush -TitleBrush $Script:TitleBrush
            $Script:HelpTitle.Text = "Tip"
            $Script:HelpBody.Text = "If the sign-in page doesn't appear, click the button above."
        }
        "Connecting" {
            $Script:StatusBadge.Background = $Script:WarningBrush
            $Script:StatusMark.Text = [String]([Char]0xE768)
            $Script:StatusCard.Background = $Script:WarningCardBrush
            $Script:StatusCard.BorderBrush = $Script:WarningBrush
            $Script:StatusText.Foreground = $Script:WarningTextBrush
            Set-NetworkButtonLabel -Label "Select`nNetwork"
            Set-StepBadge -Badge $Script:Step1Badge -Mark $Script:Step1Mark -Title $Script:Step1Title -BadgeBrush $Script:WarningBrush -MarkBrush $WhiteBrush -TitleBrush $Script:TitleBrush
            Set-StepBadge -Badge $Script:Step2Badge -Mark $Script:Step2Mark -Title $Script:Step2Title -BadgeBrush $Script:InactiveStepBrush -MarkBrush $Script:InactiveTitleBrush -TitleBrush $Script:InactiveTitleBrush
            $Script:HelpTitle.Text = "Need help?"
            $Script:HelpBody.Text = "Wait until Wi-Fi shows connected, then open the sign-in page."
        }
        "Unavailable" {
            $Script:StatusBadge.Background = $Script:IdleBrush
            $Script:StatusMark.Text = [String]([Char]0xE946)
            $Script:StatusCard.Background = [System.Windows.Media.Brushes]::WhiteSmoke
            $Script:StatusCard.BorderBrush = $Script:IdleBrush
            $Script:StatusText.Foreground = $Script:TitleBrush
            Set-NetworkButtonLabel -Label "Select`nNetwork"
            Set-StepBadge -Badge $Script:Step1Badge -Mark $Script:Step1Mark -Title $Script:Step1Title -BadgeBrush $Script:InactiveStepBrush -MarkBrush $Script:InactiveTitleBrush -TitleBrush $Script:InactiveTitleBrush
            Set-StepBadge -Badge $Script:Step2Badge -Mark $Script:Step2Mark -Title $Script:Step2Title -BadgeBrush $Script:InactiveStepBrush -MarkBrush $Script:InactiveTitleBrush -TitleBrush $Script:InactiveTitleBrush
            $Script:HelpTitle.Text = "Need help?"
            $Script:HelpBody.Text = "Wi-Fi status could not be read. Check Windows Wi-Fi settings and try again."
        }
        Default {
            $Script:StatusBadge.Background = $Script:OfflineBrush
            $Script:StatusMark.Text = [String]([Char]0xE711)
            $Script:StatusCard.Background = $Script:OfflineCardBrush
            $Script:StatusCard.BorderBrush = $Script:OfflineBrush
            $Script:StatusText.Foreground = $Script:ErrorTextBrush
            Set-NetworkButtonLabel -Label "Select`nNetwork"
            Set-StepBadge -Badge $Script:Step1Badge -Mark $Script:Step1Mark -Title $Script:Step1Title -BadgeBrush $Script:OfflineBrush -MarkBrush $WhiteBrush -TitleBrush $Script:TitleBrush
            Set-StepBadge -Badge $Script:Step2Badge -Mark $Script:Step2Mark -Title $Script:Step2Title -BadgeBrush $Script:InactiveStepBrush -MarkBrush $Script:InactiveTitleBrush -TitleBrush $Script:InactiveTitleBrush
            $Script:HelpTitle.Text = "Need help?"
            $Script:HelpBody.Text = "Turn on Wi-Fi and connect to a network (e.g. airline, hotel, café), then return here."
        }
    }
}

Function Get-WifiSnapshot { Return [WifiMonitor]::Query() }

Function Update-WifiStatus {
    If ($Script:IsClosing -Or $Script:IsUpdatingStatus) { Return }
    $Script:IsUpdatingStatus = $True
    Try {
        $Snapshot = Get-WifiSnapshot
        $Script:LinkState = [String]$Snapshot.State
        If ($Script:LinkState -Ne $Script:LastLoggedLinkState) {
            Write-SignInLog ("[INFO] Wi-Fi state is " + $Script:LinkState + ".")
            $Script:LastLoggedLinkState = $Script:LinkState
        }

        If ($Snapshot.DiagnosticCode -Ne $Script:LastLoggedDiagnostic) {
            Write-SignInLog ("[INFO] WLAN diagnostic code=" + $Snapshot.DiagnosticCode)
            $Script:LastLoggedDiagnostic = $Snapshot.DiagnosticCode
        }

        Switch ($Script:LinkState) {
        "Connected" {
            Set-WifiStatusAppearance -Kind "Connected"
            $Script:StatusText.Text = "Connected to Wi-Fi"
            $Script:NetworkText.Text = [String]$Snapshot.Detail
        }
        "Connecting" {
            Set-WifiStatusAppearance -Kind "Connecting"
            $Script:StatusText.Text = "Connecting to Wi-Fi"
            $Script:NetworkText.Text = [String]$Snapshot.Detail
        }
        "RadioOff" {
            Set-WifiStatusAppearance -Kind "Offline"
            $Script:StatusText.Text = "Not connected to Wi-Fi"
            $Script:NetworkText.Text = "Turn Wi-Fi on, then connect to a network."
        }
        "Disconnected" {
            Set-WifiStatusAppearance -Kind "Offline"
            $Script:StatusText.Text = "Not connected to Wi-Fi"
            $Script:NetworkText.Text = "Connect to a Wi-Fi network to continue."
        }
        "NoAdapter" {
            Set-WifiStatusAppearance -Kind "Offline"
            $Script:StatusText.Text = "Not connected to Wi-Fi"
            $Script:NetworkText.Text = "No Wi-Fi adapter was found."
        }
        Default {
            Set-WifiStatusAppearance -Kind "Unavailable"
            $Script:StatusText.Text = "Wi-Fi status unavailable"
            $Script:NetworkText.Text = [String]$Snapshot.Detail
        }
    }

    If ($Script:LinkState -Eq "Connected") {
        $NetworkLabel = [String](Get-ConnectedWifiLabel)
        If ($NetworkLabel.StartsWith("Network: ")) {
            $NetworkLabel = $NetworkLabel.Substring(9).Trim()
        }
        If ([String]::IsNullOrWhiteSpace($NetworkLabel) -Eq $False) {
            $Script:NetworkText.Text = $NetworkLabel
        }
    }

        Update-SignInButtonState
    }
    Catch {
        Write-SignInError -Operation "Wi-Fi status update failed" -Exception $_.Exception
        $Script:LinkState = "Unavailable"
        Set-WifiStatusAppearance -Kind "Unavailable"
        $Script:StatusText.Text = "Wi-Fi status unavailable"
        $Script:NetworkText.Text = "Could not read Wi-Fi status."
        Update-SignInButtonState
    }
    Finally { $Script:IsUpdatingStatus = $False }
}

Function Update-SignInButtonState {
    If ($Null -Eq $Script:OpenSignInButton) {
        Return
    }

    $WifiConnected = $Script:LinkState -Eq "Connected"
    $SignInBusy = $Script:IsOpening -Eq $True
    $Script:OpenSignInButton.IsEnabled = $WifiConnected -And (-Not $SignInBusy) -And (-Not $Script:IsClosing)
}

Function Start-SignInBrowser {
    $TriggerUri = $Null
    If ($Script:TriggerUrl -Match '[\s"]' -Or
        -Not [Uri]::TryCreate($Script:TriggerUrl, [UriKind]::Absolute, [Ref]$TriggerUri) -Or
        $TriggerUri.Scheme -Ne "http" -Or [String]::IsNullOrWhiteSpace($TriggerUri.Host)) {
        Throw "The sign-in trigger must be an absolute HTTP URL."
    }
    $EdgeCandidates = @()
    ForEach ($BaseFolder in @($Env:ProgramFiles, [Environment]::GetEnvironmentVariable("ProgramFiles(x86)"), $Env:LOCALAPPDATA)) {
        If (-Not [String]::IsNullOrWhiteSpace($BaseFolder)) {
            $EdgeCandidates += Join-Path $BaseFolder "Microsoft\Edge\Application\msedge.exe"
        }
    }
    ForEach ($EdgePath in ($EdgeCandidates | Select-Object -Unique)) {
        If (Test-Path -LiteralPath $EdgePath -PathType Leaf) {
            $Script:AttemptedBrowser = "Microsoft Edge"
            Write-SignInLog "[INFO] Browser launch requested: Edge."
            Start-Process -FilePath $EdgePath -ArgumentList ('"' + $Script:TriggerUrl + '"') -ErrorAction Stop
            Write-SignInLog "[INFO] Edge launch request accepted; page load and authentication are unverified."
            Return "Edge"
        }
    }
    $Script:AttemptedBrowser = "your default browser"
    Write-SignInLog "[INFO] Edge was not found; default-browser launch requested."
    Start-Process -FilePath $Script:TriggerUrl -ErrorAction Stop
    Write-SignInLog "[INFO] Default-browser launch request accepted; page load and authentication are unverified."
    Return "Default"
}

Function Open-WifiNetworks {
    Try {
        Start-Process "ms-availablenetworks:"
        Write-SignInLog "[INFO] Opened the Windows network list."
    }
    Catch {
        Try {
            Start-Process "ms-settings:network-wifi"
            Write-SignInLog "[INFO] Opened Wi-Fi settings."
        }
        Catch {
            Write-SignInError -Operation "Could not open Wi-Fi settings" -Exception $_.Exception
        }
    }
}

Function Get-SignInResultMessage {
    Param([String]$CiscoState, [String]$Browser)
    $Lead = "Opening the Wi-Fi sign-in page in your default browser."
    If ($Browser -Eq "Edge") { $Lead = "Opening the Wi-Fi sign-in page in Microsoft Edge." }
    If ($CiscoState -In @("Manual", "StillOpen")) {
        Return ($Lead + " If Cisco has a Wi-Fi sign-in window open, close that window, then try again.")
    }
    If ($Script:LinkState -Ne "Connected") {
        Return ($Lead + " Check your Wi-Fi connection if the page does not load.")
    }
    Return $Lead
}

Function Complete-SignInLaunch {
    Param([String]$CiscoState)
    If ($Script:IsClosing) { Return }
    Try {
        $Script:AttemptedBrowser = "the browser"
        $Browser = Start-SignInBrowser
        If ($CiscoState -In @("Manual", "StillOpen") -Or $Browser -Ne "Edge" -Or $Script:LinkState -Ne "Connected") {
            Show-ActionResult -Message (Get-SignInResultMessage -CiscoState $CiscoState -Browser $Browser) -Foreground $Script:WarningTextBrush
        }
        Else { $Script:ResultText.Visibility = [System.Windows.Visibility]::Collapsed }
    }
    Catch {
        Write-SignInError -Operation ("Launch failed: " + $Script:AttemptedBrowser) -Exception $_.Exception
        Show-ActionResult -Message ("Could not open " + $Script:AttemptedBrowser + ". Open your browser and visit http://neverssl.com to try signing in.") -Foreground $Script:ErrorTextBrush
    }
    Finally {
        If (-Not $Script:IsClosing -And $Null -Ne $Script:Cooldown) {
            $Script:Cooldown.Stop()
            $Script:Cooldown.Start()
        }
    }
}

Function Get-CiscoCloseState { Return [CiscoBrowserCloser]::Poll() }

Function Get-CiscoNoticeState { Return [CiscoFailoverNotice]::Poll() }

Function Complete-SignInAfterCiscoClose {
    If ($Script:IsClosing -Or $Script:CiscoCloseFinished) { Return }
    Try {
        $CiscoState = Get-CiscoCloseState
        If ($CiscoState -Eq "Waiting") { Return }
        Write-SignInLog ("[INFO] Cisco close outcome=" + $CiscoState + "; code=" + [CiscoBrowserCloser]::LastError)
    }
    Catch {
        Write-SignInError -Operation "Cisco close operation failed; continuing with manual handling" -Exception $_.Exception
        $CiscoState = "Manual"
    }
    $Script:CiscoCloseFinished = $True
    $Script:CiscoCloseTimer.Stop()
    [CiscoBrowserCloser]::Stop()
    Complete-SignInLaunch -CiscoState $CiscoState
}

Function Invoke-SignInPage {
    If ($Script:IsClosing -Or $Script:IsOpening) { Return }
    Update-WifiStatus
    If ($Script:LinkState -Ne "Connected") { Return }
    $Script:IsOpening = $True
    Update-SignInButtonState
    Write-SignInLog "[INFO] Open sign-in page clicked."
    Try {
        Start-FailoverNoticeMonitor
        [CiscoBrowserCloser]::Begin()
        $Script:CiscoCloseFinished = $False
        $Script:CiscoCloseTimer.Start()
        Complete-SignInAfterCiscoClose
    }
    Catch {
        Write-SignInError -Operation "Sign-in preparation failed; continuing with manual handling" -Exception $_.Exception
        $Script:CiscoCloseTimer.Stop()
        [CiscoBrowserCloser]::Stop()
        Complete-SignInLaunch -CiscoState "Manual"
    }
}

Function Get-SignInWorkArea {
    $Area = [System.Windows.SystemParameters]::WorkArea
    $Source = [System.Windows.PresentationSource]::FromVisual($Script:Window)
    If ($Null -Ne $Source -And $Null -Ne $Source.CompositionTarget) {
        $Helper = New-Object System.Windows.Interop.WindowInteropHelper $Script:Window
        $Pixels = [WindowWorkArea]::Get($Helper.Handle)
        If ($Null -Ne $Pixels) {
            $Transform = $Source.CompositionTarget.TransformFromDevice
            $First = $Transform.Transform((New-Object System.Windows.Point $Pixels[0], $Pixels[1]))
            $Last = $Transform.Transform((New-Object System.Windows.Point $Pixels[2], $Pixels[3]))
            $Area = New-Object System.Windows.Rect $First, $Last
        }
    }
    Return $Area
}

Function Update-WindowBounds {
    If ($Script:IsClosing -Or $Script:IsUpdatingBounds -Or $Null -Eq $Script:Window) { Return }
    $Script:IsUpdatingBounds = $True
    Try {
        $Area = Get-SignInWorkArea
        $PreferredWidth = $Script:PreferredWindowWidth
        If ($PreferredWidth -Le 0) { $PreferredWidth = 520 }
        $Script:Window.MaxWidth = [Math]::Max(1, $Area.Width - 4)
        $Script:Window.MaxHeight = [Math]::Max(1, $Area.Height - 4)
        $Script:Window.Width = [Math]::Min($PreferredWidth, $Script:Window.MaxWidth)
        $Header = $Script:Window.FindName("HeaderBanner")
        If ($Null -Ne $Header.Source -And $Script:BannerAspect -Gt 0) {
            $Header.Width = [Math]::Max(1, $Script:Window.Width - 30)
            $Header.Height = [Math]::Round($Header.Width * $Script:BannerAspect)
        }
        $Scroller = $Script:Window.FindName("ContentScroller")
        $Content = $Script:Window.FindName("MainContent")
        If ($Script:Window.Width -Lt $PreferredWidth) {
            $Content.Width = [Math]::Max(1, $PreferredWidth - 54)
            $Scroller.HorizontalScrollBarVisibility = [System.Windows.Controls.ScrollBarVisibility]::Auto
        }
        Else {
            $Content.Width = [Double]::NaN
            $Scroller.HorizontalScrollBarVisibility = [System.Windows.Controls.ScrollBarVisibility]::Disabled
        }
        $Width = [Math]::Min($Script:Window.Width, $Area.Width)
        $Height = [Math]::Min($Script:Window.ActualHeight, $Script:Window.MaxHeight)
        If (-Not [Double]::IsNaN($Script:Window.Left)) {
            $Script:Window.Left = [Math]::Max($Area.Left, [Math]::Min($Script:Window.Left, $Area.Right - $Width))
        }
        If (-Not [Double]::IsNaN($Script:Window.Top)) {
            $Script:Window.Top = [Math]::Max($Area.Top, [Math]::Min($Script:Window.Top, $Area.Bottom - $Height))
        }
    }
    Finally { $Script:IsUpdatingBounds = $False }
}

Function Move-SignInWindowToTopRight {
    $Area = [System.Windows.SystemParameters]::WorkArea
    $Script:Window.Left = $Area.Left
    $Script:Window.Top = $Area.Top
    Update-WindowBounds
    $Script:Window.UpdateLayout()
    $Script:Window.Left = [Math]::Max($Area.Left, $Area.Right - $Script:Window.ActualWidth - 2)
    $Script:Window.Top = $Area.Top + 2
    Update-WindowBounds
}

Function Update-WindowCornerClip {
    If ($Null -Eq $Script:WindowSurface) {
        Return
    }

    $SurfaceWidth = $Script:WindowSurface.ActualWidth
    $SurfaceHeight = $Script:WindowSurface.ActualHeight
    If (($SurfaceWidth -Le 1) -Or ($SurfaceHeight -Le 1)) {
        Return
    }

    $ClipGeometry = New-Object System.Windows.Media.RectangleGeometry
    $ClipGeometry.RadiusX = 11
    $ClipGeometry.RadiusY = 11
    $ClipGeometry.Rect = New-Object System.Windows.Rect 0, 0, $SurfaceWidth, $SurfaceHeight
    $Script:WindowSurface.Clip = $ClipGeometry
}

Function Start-FailoverNoticeMonitor {
    If ($Script:IsClosing) { Return }
    $Script:FailoverNoticeTimer.Stop()
    [CiscoFailoverNotice]::Begin()
    $Script:LastNoticeState = ""
    $Script:FailoverNoticeClock = [Diagnostics.Stopwatch]::StartNew()
    $Script:FailoverNoticeTimer.Start()
    Write-SignInLog "[INFO] Cisco notice monitor started; five-second limit."
}

Function Update-FailoverNoticeMonitor {
    If ($Script:IsClosing) { Return }
    Try {
        If ($Script:FailoverNoticeClock.Elapsed.TotalSeconds -Ge 5) {
            $Script:FailoverNoticeTimer.Stop()
            [CiscoFailoverNotice]::Stop()
            Write-SignInLog "[INFO] Cisco notice monitor timed out; no dismissal confirmed."
            Return
        }
        $State = Get-CiscoNoticeState
        If ($State -Ne $Script:LastNoticeState) {
            Write-SignInLog ("[INFO] Cisco notice outcome=" + $State + "; code=" + [CiscoFailoverNotice]::LastError)
            $Script:LastNoticeState = $State
        }
        If ($State -In @("Dismissed", "Manual")) {
            $Script:FailoverNoticeTimer.Stop()
            [CiscoFailoverNotice]::Stop()
        }
    }
    Catch {
        $Script:FailoverNoticeTimer.Stop()
        Write-SignInError -Operation "Cisco notice monitor failed; manual handling is available" -Exception $_.Exception
    }
}

Function Initialize-SignInTimers {
    $Script:Timer = New-Object System.Windows.Threading.DispatcherTimer
    $Script:Timer.Interval = [TimeSpan]::FromSeconds(2)
    $Script:Timer.Add_Tick({ Update-WifiStatus; Update-WindowBounds })
    $Script:CiscoCloseTimer = New-Object System.Windows.Threading.DispatcherTimer
    $Script:CiscoCloseTimer.Interval = [TimeSpan]::FromMilliseconds(250)
    $Script:CiscoCloseTimer.Add_Tick({ Complete-SignInAfterCiscoClose })
    $Script:FailoverNoticeTimer = New-Object System.Windows.Threading.DispatcherTimer
    $Script:FailoverNoticeTimer.Interval = [TimeSpan]::FromMilliseconds(250)
    $Script:FailoverNoticeTimer.Add_Tick({ Update-FailoverNoticeMonitor })
    $Script:Cooldown = New-Object System.Windows.Threading.DispatcherTimer
    $Script:Cooldown.Interval = [TimeSpan]::FromSeconds(1)
    $Script:Cooldown.Add_Tick({
        $Script:Cooldown.Stop()
        If (-Not $Script:IsClosing) {
            $Script:IsOpening = $False
            Update-SignInButtonState
        }
    })
}

Function Close-SignInWindow {
    If ($Script:IsClosing) { Return }
    $Script:IsClosing = $True
    ForEach ($TimerName in @("Timer", "CiscoCloseTimer", "FailoverNoticeTimer", "Cooldown")) {
        $TimerVariable = Get-Variable -Name $TimerName -Scope Script -ErrorAction SilentlyContinue
        If ($Null -Ne $TimerVariable -And $Null -Ne $TimerVariable.Value) { $TimerVariable.Value.Stop() }
    }
    If ($Null -Ne ([System.Management.Automation.PSTypeName]"NetworkChangeRelay").Type) { [NetworkChangeRelay]::Stop() }
    If ($Null -Ne ([System.Management.Automation.PSTypeName]"CiscoBrowserCloser").Type) { [CiscoBrowserCloser]::Stop() }
    If ($Null -Ne ([System.Management.Automation.PSTypeName]"CiscoFailoverNotice").Type) { [CiscoFailoverNotice]::Stop() }
    If ($Null -Ne $Script:FailoverNoticeClock) { $Script:FailoverNoticeClock.Stop() }
    Write-SignInLog "[INFO] All timers stopped and network events detached."
}

Function Set-WindowArtwork {
    $AssetFolder = Join-Path $Script:AppFolder "Assets"
    $TitleIconPath = Join-Path $AssetFolder "TitleIcon.png"
    $TitleIcon = $Script:Window.FindName("TitleIcon")

    If ((Test-Path -LiteralPath $TitleIconPath) -Eq $False) {
        Write-SignInLog "[WARN] App icon was not found. The window will open without it."
    }
    Else {
        Try {
            $TitleImage = New-Object System.Windows.Media.Imaging.BitmapImage
            $TitleImage.BeginInit()
            $TitleImage.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
            $TitleImage.UriSource = New-Object System.Uri $TitleIconPath
            $TitleImage.EndInit()
            $TitleImage.Freeze()
            $Script:Window.Icon = $TitleImage
            If ($Null -Ne $TitleIcon) {
                $TitleIcon.Source = $TitleImage
            }
        }
        Catch {
            Write-SignInError -Operation "App icon could not be loaded" -Exception $_.Exception
        }
    }

    $HeaderPath = Join-Path $AssetFolder "HeaderBanner.png"
    $HeaderBanner = $Script:Window.FindName("HeaderBanner")
    If ((Test-Path -LiteralPath $HeaderPath) -Eq $False) {
        Write-SignInLog "[WARN] Header banner was not found."
        Return
    }

    Try {
        $HeaderImage = New-Object System.Windows.Media.Imaging.BitmapImage
        $HeaderImage.BeginInit()
        $HeaderImage.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $HeaderImage.UriSource = New-Object System.Uri $HeaderPath
        $HeaderImage.EndInit()
        $HeaderImage.Freeze()
        If ($Null -Ne $HeaderBanner) {
            $ShadowMargin = 14
            $FrameThickness = 1
            $ContentMargin = 12
            $BannerScale = 3.0
            $ContentWidth = [Math]::Round([Double]$HeaderImage.PixelWidth / $BannerScale)
            $BannerWidth = $ContentWidth + ($ContentMargin * 2)
            $BannerHeight = [Math]::Round($BannerWidth * [Double]$HeaderImage.PixelHeight / [Double]$HeaderImage.PixelWidth)
            $HeaderBanner.Stretch = [System.Windows.Media.Stretch]::Uniform
            $HeaderBanner.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Stretch
            $HeaderBanner.VerticalAlignment = [System.Windows.VerticalAlignment]::Top
            $HeaderBanner.Margin = New-Object System.Windows.Thickness 0
            $HeaderBanner.Width = $BannerWidth
            $HeaderBanner.Height = $BannerHeight
            [System.Windows.Media.RenderOptions]::SetBitmapScalingMode($HeaderBanner, [System.Windows.Media.BitmapScalingMode]::Fant)
            $Script:Window.Width = $BannerWidth + (($ShadowMargin + $FrameThickness) * 2)
            $Script:PreferredWindowWidth = $Script:Window.Width
            $Script:BannerAspect = [Double]$HeaderImage.PixelHeight / [Double]$HeaderImage.PixelWidth
            $HeaderBanner.Source = $HeaderImage
        }
    }
    Catch {
        Write-SignInError -Operation "Header banner could not be loaded" -Exception $_.Exception
    }
}

$Script:ConnectedBrush = New-FrozenBrush -Red 0x1F -Green 0x8A -Blue 0x4C
$Script:IdleBrush = New-FrozenBrush -Red 0x9A -Green 0xA3 -Blue 0xAF
$Script:WarningBrush = New-FrozenBrush -Red 0xC4 -Green 0x7B -Blue 0x00
$Script:OfflineBrush = New-FrozenBrush -Red 0xCA -Green 0x24 -Blue 0x20
$Script:ConnectedCardBrush = New-FrozenBrush -Red 0xE7 -Green 0xF6 -Blue 0xEE
$Script:WarningCardBrush = New-FrozenBrush -Red 0xFF -Green 0xF4 -Blue 0xE5
$Script:OfflineCardBrush = New-FrozenBrush -Red 0xFD -Green 0xEC -Blue 0xEC
$Script:TitleBrush = New-FrozenBrush -Red 0x1A -Green 0x23 -Blue 0x32
$Script:InactiveStepBrush = New-FrozenBrush -Red 0xE1 -Green 0xE5 -Blue 0xEA
$Script:InactiveTitleBrush = New-FrozenBrush -Red 0x9A -Green 0xA3 -Blue 0xAF
$Script:SuccessTextBrush = New-FrozenBrush -Red 0x1F -Green 0x6B -Blue 0x3A
$Script:WarningTextBrush = New-FrozenBrush -Red 0x8A -Green 0x4B -Blue 0x08
$Script:ErrorTextBrush = New-FrozenBrush -Red 0xA1 -Green 0x26 -Blue 0x22

$WindowXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Wi-Fi Assist"
        Width="520"
        SizeToContent="Height"
        WindowStartupLocation="Manual"
        WindowStyle="None"
        AllowsTransparency="True"
        Topmost="True"
        ResizeMode="CanMinimize"
        Background="Transparent"
        FontFamily="Segoe UI"
        FontSize="13"
        UseLayoutRounding="True"
        SnapsToDevicePixels="True"
        TextOptions.TextFormattingMode="Display">
    <Window.Resources>
        <Style x:Key="CaptionButtonStyle" TargetType="Button">
            <Setter Property="Width" Value="46" />
            <Setter Property="Height" Value="44" />
            <Setter Property="Background" Value="Transparent" />
            <Setter Property="Foreground" Value="#1A2332" />
            <Setter Property="BorderThickness" Value="0" />
            <Setter Property="FontFamily" Value="Segoe MDL2 Assets" />
            <Setter Property="FontSize" Value="10" />
            <Setter Property="Focusable" Value="False" />
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Chrome"
                                Background="{TemplateBinding Background}"
                                SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Center"
                                              VerticalAlignment="Center"
                                              TextElement.Foreground="{TemplateBinding Foreground}" />
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Chrome" Property="Background" Value="#F0F2F4" />
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="Chrome" Property="Background" Value="#E4E7EB" />
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="CloseButtonStyle" TargetType="Button" BasedOn="{StaticResource CaptionButtonStyle}">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Chrome"
                                Background="{TemplateBinding Background}"
                                SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Center"
                                              VerticalAlignment="Center"
                                              TextElement.Foreground="{TemplateBinding Foreground}" />
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Chrome" Property="Background" Value="#CA2420" />
                                <Setter Property="Foreground" Value="White" />
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="Chrome" Property="Background" Value="#8E1916" />
                                <Setter Property="Foreground" Value="White" />
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="SecondaryButtonStyle" TargetType="Button">
            <Setter Property="Background" Value="White" />
            <Setter Property="Foreground" Value="#1A2332" />
            <Setter Property="FontSize" Value="12" />
            <Setter Property="FontWeight" Value="SemiBold" />
            <Setter Property="MinWidth" Value="76" />
            <Setter Property="MinHeight" Value="44" />
            <Setter Property="Padding" Value="8,4" />
            <Setter Property="Cursor" Value="Hand" />
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Border"
                                Background="{TemplateBinding Background}"
                                BorderBrush="#D5DBE3"
                                BorderThickness="1"
                                CornerRadius="8"
                                SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Center"
                                              VerticalAlignment="Center"
                                              TextElement.Foreground="{TemplateBinding Foreground}"
                                              TextElement.FontWeight="{TemplateBinding FontWeight}" />
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#F7F8FA" />
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#EEF1F4" />
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="SignInButtonStyle" TargetType="Button">
            <Setter Property="Background" Value="#CA2420" />
            <Setter Property="Foreground" Value="White" />
            <Setter Property="FontSize" Value="15" />
            <Setter Property="FontWeight" Value="SemiBold" />
            <Setter Property="Height" Value="46" />
            <Setter Property="Cursor" Value="Hand" />
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Border"
                                Background="{TemplateBinding Background}"
                                CornerRadius="8"
                                SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Center"
                                              VerticalAlignment="Center"
                                              TextElement.Foreground="{TemplateBinding Foreground}"
                                              TextElement.FontWeight="{TemplateBinding FontWeight}" />
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#A81E1B" />
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#8E1916" />
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Border" Property="Background" Value="#E6E9ED" />
                                <Setter Property="Foreground" Value="#6B7380" />
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    <Grid Margin="14">
        <Border CornerRadius="12"
                Background="White"
                BorderBrush="#D5DBE3"
                BorderThickness="1"
                SnapsToDevicePixels="True">
            <Border.Effect>
                <DropShadowEffect BlurRadius="16"
                                  ShadowDepth="0"
                                  Opacity="0.18"
                                  Color="#1A2332" />
            </Border.Effect>
            <Grid x:Name="WindowSurface">
            <Grid.RowDefinitions>
                <RowDefinition Height="44" />
                <RowDefinition Height="Auto" />
                <RowDefinition Height="*" />
            </Grid.RowDefinitions>

            <Grid x:Name="TitleBar" Background="White">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto" />
                    <ColumnDefinition Width="*" />
                    <ColumnDefinition Width="Auto" />
                </Grid.ColumnDefinitions>
                <Image x:Name="TitleIcon"
                       Width="22"
                       Height="22"
                       Margin="14,0,0,0"
                       VerticalAlignment="Center"
                       RenderOptions.BitmapScalingMode="HighQuality"
                       SnapsToDevicePixels="True" />
                <TextBlock Grid.Column="1"
                           Margin="10,0,8,0"
                           VerticalAlignment="Center"
                           Text="Wi-Fi Assist"
                           FontSize="13"
                           FontWeight="SemiBold"
                           Foreground="#1A2332"
                           TextTrimming="CharacterEllipsis" />
                <StackPanel Grid.Column="2" Orientation="Horizontal">
                    <Button x:Name="MinimizeButton"
                            Style="{StaticResource CaptionButtonStyle}"
                            Content="&#xE921;"
                            AutomationProperties.AutomationId="MinimizeButton"
                            AutomationProperties.Name="Minimize" />
                    <Button x:Name="CloseButton"
                            Style="{StaticResource CloseButtonStyle}"
                            Content="&#xE8BB;"
                            AutomationProperties.AutomationId="CloseButton"
                            AutomationProperties.Name="Close" />
                </StackPanel>
                <Border Grid.ColumnSpan="3"
                        Height="1"
                        VerticalAlignment="Bottom"
                        Background="#E6E9ED"
                        IsHitTestVisible="False" />
            </Grid>

            <Image x:Name="HeaderBanner"
                   Grid.Row="1"
                   Stretch="Uniform"
                   HorizontalAlignment="Stretch"
                   VerticalAlignment="Top"
                   SnapsToDevicePixels="True" />

            <ScrollViewer x:Name="ContentScroller" Grid.Row="2" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" Focusable="False">
            <StackPanel x:Name="MainContent" Margin="12,16,12,18">
                    <Grid Margin="10,0,10,0">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto" />
                            <ColumnDefinition Width="*" />
                            <ColumnDefinition Width="Auto" />
                        </Grid.ColumnDefinitions>
                        <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                            <Border x:Name="Step1Badge" Width="28" Height="28" CornerRadius="14" Background="#CA2420">
                                <TextBlock x:Name="Step1Mark" Text="1" Foreground="White" FontWeight="Bold" FontSize="13" HorizontalAlignment="Center" VerticalAlignment="Center" />
                            </Border>
                            <StackPanel Margin="8,0,0,0" VerticalAlignment="Center">
                                <TextBlock x:Name="Step1Title" Text="Connect to Wi-Fi" FontSize="13" FontWeight="SemiBold" Foreground="#1A2332" />
                                <TextBlock x:Name="Step1Detail" Text="Join a Wi-Fi network" Margin="0,1,0,0" FontSize="11" Foreground="#8B95A1" />
                            </StackPanel>
                        </StackPanel>
                        <Path Grid.Column="1"
                              Margin="8,0"
                              Width="12"
                              Height="18"
                              HorizontalAlignment="Center"
                              VerticalAlignment="Center"
                              Stretch="Fill"
                              Stroke="#9AA3AF"
                              StrokeThickness="2.4"
                              StrokeStartLineCap="Round"
                              StrokeEndLineCap="Round"
                              StrokeLineJoin="Round"
                              Data="M 1,1 L 8,9 L 1,17" />
                        <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                            <Border x:Name="Step2Badge" Width="28" Height="28" CornerRadius="14" Background="#E1E5EA">
                                <TextBlock x:Name="Step2Mark" Text="2" Foreground="#9AA3AF" FontWeight="Bold" FontSize="13" HorizontalAlignment="Center" VerticalAlignment="Center" />
                            </Border>
                            <StackPanel Margin="8,0,0,0" VerticalAlignment="Center">
                                <TextBlock x:Name="Step2Title" Text="Open Wi-Fi Sign-In" FontSize="13" FontWeight="SemiBold" Foreground="#9AA3AF" />
                                <TextBlock x:Name="Step2Detail" Text="Let Wi-Fi Assist do the rest" Margin="0,1,0,0" FontSize="11" Foreground="#8B95A1" TextWrapping="Wrap" />
                            </StackPanel>
                        </StackPanel>
                    </Grid>

                    <Border x:Name="StatusCard"
                            Margin="0,16,0,0"
                            Background="#FDECEC"
                            BorderBrush="#CA2420"
                            BorderThickness="2"
                            CornerRadius="10"
                            Padding="14,14">
                        <Grid VerticalAlignment="Center">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto" />
                                <ColumnDefinition Width="*" />
                                <ColumnDefinition Width="Auto" />
                            </Grid.ColumnDefinitions>
                            <Border x:Name="StatusBadge"
                                    Width="42"
                                    Height="42"
                                    CornerRadius="21"
                                    Background="#CA2420"
                                    VerticalAlignment="Center"
                                    AutomationProperties.AutomationId="WifiStatusDot">
                                <TextBlock x:Name="StatusMark"
                                           Text="&#xE711;"
                                           FontFamily="Segoe MDL2 Assets"
                                           FontSize="18"
                                           Foreground="White"
                                           HorizontalAlignment="Center"
                                           VerticalAlignment="Center"
                                           AutomationProperties.AutomationId="WifiStatusMark" />
                            </Border>
                            <StackPanel Grid.Column="1" Margin="14,0,10,0" VerticalAlignment="Center">
                                <TextBlock x:Name="StatusText"
                                           Text="Checking Wi-Fi..."
                                           FontSize="16"
                                           FontWeight="SemiBold"
                                           Foreground="#1A2332"
                                           TextWrapping="Wrap"
                                           AutomationProperties.AutomationId="WifiStatusText" />
                                <TextBlock x:Name="NetworkText"
                                           Margin="0,2,0,0"
                                           FontSize="13"
                                           Foreground="#5E6874"
                                           TextWrapping="Wrap"
                                           AutomationProperties.AutomationId="NetworkText" />
                            </StackPanel>
                            <Button x:Name="ChangeNetworkButton"
                                    Grid.Column="2"
                                    Style="{StaticResource SecondaryButtonStyle}"
                                    VerticalAlignment="Center"
                                    AutomationProperties.AutomationId="ChangeNetworkButton"
                                    AutomationProperties.Name="Select Network">
                                <TextBlock x:Name="ChangeNetworkLabel" Text="Select&#x0a;Network" TextAlignment="Center" FontSize="12" FontWeight="SemiBold" />
                            </Button>
                        </Grid>
                    </Border>

                    <Button x:Name="OpenSignInButton"
                            Margin="0,16,0,0"
                            Style="{StaticResource SignInButtonStyle}"
                            IsEnabled="False"
                            IsDefault="True"
                            AutomationProperties.AutomationId="OpenSignInButton"
                            AutomationProperties.Name="Open Wi-Fi Sign-In">
                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                            <TextBlock Text="&#xE8A7;" FontFamily="Segoe MDL2 Assets" FontSize="14" Margin="0,1,8,0" VerticalAlignment="Center" />
                            <TextBlock Text="Open Wi-Fi Sign-In" VerticalAlignment="Center" />
                        </StackPanel>
                    </Button>

                    <TextBlock Margin="0,8,0,0"
                               FontSize="12"
                               Foreground="#8B95A1"
                               HorizontalAlignment="Center"
                               Text="Opens the Wi-Fi sign-in page in Microsoft Edge." />

                    <TextBlock x:Name="ResultText"
                               Margin="0,10,0,0"
                               FontSize="12"
                               TextWrapping="Wrap"
                               Visibility="Collapsed"
                               AutomationProperties.AutomationId="ActionResultText" />

                    <Grid Margin="0,16,0,0">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto" />
                            <ColumnDefinition Width="*" />
                        </Grid.ColumnDefinitions>
                        <Border Width="22" Height="22" CornerRadius="11" Background="#1B6FD4" VerticalAlignment="Top">
                            <TextBlock Text="i" FontWeight="Bold" FontStyle="Italic" FontSize="13" Foreground="White" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="0,-1,0,0" />
                        </Border>
                        <StackPanel Grid.Column="1" Margin="10,0,0,0">
                            <TextBlock x:Name="HelpTitle" Text="Need help?" FontSize="13" FontWeight="Bold" Foreground="#1A2332" />
                            <TextBlock x:Name="HelpBody"
                                       Margin="0,2,0,0"
                                       FontSize="12"
                                       Foreground="#5E6874"
                                       TextWrapping="Wrap"
                                       Text="Turn on Wi-Fi and connect to a network (e.g. airline, hotel, café), then return here." />
                        </StackPanel>
                    </Grid>
            </StackPanel>
            </ScrollViewer>
            </Grid>
        </Border>
    </Grid>
</Window>
'@

$Script:Window = [System.Windows.Markup.XamlReader]::Parse($WindowXaml)
$Script:StatusCard = $Script:Window.FindName("StatusCard")
$Script:StatusBadge = $Script:Window.FindName("StatusBadge")
$Script:StatusMark = $Script:Window.FindName("StatusMark")
$Script:StatusText = $Script:Window.FindName("StatusText")
$Script:NetworkText = $Script:Window.FindName("NetworkText")
$Script:OpenSignInButton = $Script:Window.FindName("OpenSignInButton")
$Script:ResultText = $Script:Window.FindName("ResultText")
$Script:Step1Badge = $Script:Window.FindName("Step1Badge")
$Script:Step1Mark = $Script:Window.FindName("Step1Mark")
$Script:Step1Title = $Script:Window.FindName("Step1Title")
$Script:Step2Badge = $Script:Window.FindName("Step2Badge")
$Script:Step2Mark = $Script:Window.FindName("Step2Mark")
$Script:Step2Title = $Script:Window.FindName("Step2Title")
$Script:ChangeNetworkButton = $Script:Window.FindName("ChangeNetworkButton")
$Script:ChangeNetworkLabel = $Script:Window.FindName("ChangeNetworkLabel")
$Script:HelpTitle = $Script:Window.FindName("HelpTitle")
$Script:HelpBody = $Script:Window.FindName("HelpBody")
$Script:MinimizeButton = $Script:Window.FindName("MinimizeButton")
$Script:CloseButton = $Script:Window.FindName("CloseButton")
$Script:WindowSurface = $Script:Window.FindName("WindowSurface")
$Script:TitleBar = $Script:Window.FindName("TitleBar")

If (($Null -Eq $Script:StatusCard) -Or ($Null -Eq $Script:StatusBadge) -Or ($Null -Eq $Script:StatusMark) -Or ($Null -Eq $Script:StatusText) -Or ($Null -Eq $Script:NetworkText) -Or ($Null -Eq $Script:OpenSignInButton) -Or ($Null -Eq $Script:ResultText) -Or ($Null -Eq $Script:Step1Badge) -Or ($Null -Eq $Script:Step1Mark) -Or ($Null -Eq $Script:Step1Title) -Or ($Null -Eq $Script:Step2Badge) -Or ($Null -Eq $Script:Step2Mark) -Or ($Null -Eq $Script:Step2Title) -Or ($Null -Eq $Script:ChangeNetworkButton) -Or ($Null -Eq $Script:ChangeNetworkLabel) -Or ($Null -Eq $Script:HelpTitle) -Or ($Null -Eq $Script:HelpBody) -Or ($Null -Eq $Script:MinimizeButton) -Or ($Null -Eq $Script:CloseButton) -Or ($Null -Eq $Script:WindowSurface) -Or ($Null -Eq $Script:TitleBar)) {
    Write-SignInLog "[ERROR] The sign-in window could not be loaded."
    Write-Error "[ERROR] The sign-in window could not be loaded."
    Exit 1
}

Set-WindowArtwork
$Script:OpenSignInButton.Add_Click({ Invoke-SignInPage })
$Script:ChangeNetworkButton.Add_Click({ Open-WifiNetworks })
$Script:MinimizeButton.Add_Click({
    $Script:Window.WindowState = [System.Windows.WindowState]::Minimized
})
$Script:CloseButton.Add_Click({
    $Script:Window.Close()
})
$Script:TitleBar.Add_MouseLeftButtonDown({
    Param($Sender, $EventArgs)
    If ($EventArgs.ButtonState -Eq [System.Windows.Input.MouseButtonState]::Pressed) {
        Try {
            $Script:Window.DragMove()
        }
        Catch {
            Write-SignInError -Operation "Window drag did not start" -Exception $_.Exception
        }
    }
})
$Script:Window.Add_SizeChanged({ Update-WindowCornerClip; Update-WindowBounds })
$Script:Window.Add_StateChanged({
    If ($Script:Window.WindowState -Eq [System.Windows.WindowState]::Maximized) {
        $Script:Window.WindowState = [System.Windows.WindowState]::Normal
        Move-SignInWindowToTopRight
    }
})
$Script:Window.Add_Loaded({
    Move-SignInWindowToTopRight
    Update-WindowCornerClip
    Write-SignInLog "[INFO] Sign-in window loaded."
    Update-WifiStatus
    $Script:Timer.Start()
})
$Script:Window.Add_Activated({ Update-WifiStatus; Update-WindowBounds })
$Script:Window.Add_Closed({
    Write-SignInLog "[INFO] Sign-in window Closed event."
    Close-SignInWindow
})
$Script:Window.Dispatcher.Add_UnhandledException({
    Param($Sender, $EventArgs)
    Write-SignInError -Operation "Unexpected dispatcher exception; closing safely" -Exception $EventArgs.Exception
    $Script:ExitCode = 1
    $EventArgs.Handled = $True
    $Script:Window.Close()
})
$Script:Window.Dispatcher.Add_ShutdownStarted({
    Write-SignInLog "[INFO] Dispatcher shutdown started."
})

Initialize-SignInTimers

$Script:OnNetworkChanged = {
    If (-Not $Script:IsClosing) { Update-WifiStatus }
}
[NetworkChangeRelay]::Start($Script:Window.Dispatcher, [System.Action]$Script:OnNetworkChanged)

Write-SignInLog "[INFO] Opening the captive portal sign-in window."
Write-Host "[INFO] Opening the captive portal sign-in window."
$Script:Window.ShowDialog() | Out-Null
Write-SignInLog "[INFO] ShowDialog returned."
} # Startup and WPF lifetime
Catch {
    $Script:ExitCode = 1
    Write-SignInError -Operation "Application startup or window failed" -Exception $_.Exception
    Write-Warning "Wi-Fi Assist could not continue. See the diagnostic log in your temporary folder."
}
Finally {
    If (Get-Command Close-SignInWindow -CommandType Function -ErrorAction SilentlyContinue) { Close-SignInWindow }
    Write-SignInLog ("[INFO] Sign-in script is exiting; code=" + $Script:ExitCode)
    [SignInDiagnostics]::Stop()
}
Exit $Script:ExitCode
