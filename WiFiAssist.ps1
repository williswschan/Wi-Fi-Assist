#Requires -Version 5.1

Param(
    [Switch]$StaHost
)

$ErrorActionPreference = "Stop"
$Script:LogLock = New-Object System.Object
$Script:LastLoggedLinkState = ""
$TempFolder = $Env:TEMP
If ([String]::IsNullOrWhiteSpace($TempFolder)) {
    $TempFolder = [System.IO.Path]::GetTempPath()
}
$Script:LogPath = Join-Path $TempFolder "WiFiAssist.log"

Function Write-SignInLog {
    Param(
        [String]$Message
    )

    If ([String]::IsNullOrWhiteSpace($Script:LogPath)) {
        Return
    }

    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $Line = "[" + $Stamp + "] " + $Message + [System.Environment]::NewLine
    [System.Threading.Monitor]::Enter($Script:LogLock)
    Try {
        $Utf8 = New-Object System.Text.UTF8Encoding $False
        [System.IO.File]::AppendAllText($Script:LogPath, $Line, $Utf8)
    }
    Catch {
    }
    Finally {
        [System.Threading.Monitor]::Exit($Script:LogLock)
    }
}

[System.AppDomain]::CurrentDomain.Add_UnhandledException({
    Param($Sender, $EventArgs)
    $ExceptionText = ""
    If ($Null -Ne $EventArgs.ExceptionObject) {
        $ExceptionText = $EventArgs.ExceptionObject.ToString()
    }
    Write-SignInLog ("[ERROR] Process unhandled exception. Terminating=" + $EventArgs.IsTerminating + ". " + $ExceptionText)
})

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
        $PSCommandPath,
        "-StaHost"
    )
    Start-Process -FilePath $WindowsPowerShell -ArgumentList $ArgumentList -WindowStyle Hidden | Out-Null
    Exit 0
}

Write-SignInLog ("[INFO] Sign-in script started. PID=" + $PID + ". ErrorAction=Stop.")

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
}

public static class WifiMonitor
{
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
        try
        {
            return QueryCore();
        }
        catch (Exception)
        {
            return new WifiSnapshot("Unavailable", "Could not read Wi-Fi status.");
        }
    }

    private static WifiSnapshot QueryCore()
    {
        uint negotiatedVersion;
        IntPtr handle;
        int openResult = NativeMethods.WlanOpenHandle(ClientVersion, IntPtr.Zero, out negotiatedVersion, out handle);
        if (openResult != ErrorSuccess)
        {
            return new WifiSnapshot("Unavailable", DescribeApiError(openResult));
        }

        try
        {
            IntPtr listPointer;
            int enumResult = NativeMethods.WlanEnumInterfaces(handle, IntPtr.Zero, out listPointer);
            if (enumResult != ErrorSuccess)
            {
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
            if (bytes.Length != 4 || bytes[0] == 0)
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
            return !address.IsIPv6LinkLocal;
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
        if (dataSize < ProfileNameOffset + 2)
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
using System.Runtime.InteropServices;

public static class CiscoBrowserCloser
{
    private static List<IntPtr> FoundHandles = new List<IntPtr>();
    private static List<int> ProcessIds = new List<int>();
    private static EnumWindowsProc WindowCallback = OnWindow;

    public static int RequestClose()
    {
        List<IntPtr> handles = ListVisibleWindows();
        int requested = 0;
        for (int index = 0; index < handles.Count; index++)
        {
            if (PostMessage(handles[index], 0x0010, IntPtr.Zero, IntPtr.Zero))
            {
                requested++;
            }
        }

        return requested;
    }

    public static bool HasVisibleWindow()
    {
        return ListVisibleWindows().Count > 0;
    }

    private static List<IntPtr> ListVisibleWindows()
    {
        ProcessIds.Clear();
        Process[] processes = Process.GetProcessesByName("acwebhelper");
        for (int index = 0; index < processes.Length; index++)
        {
            try
            {
                ProcessIds.Add(processes[index].Id);
            }
            finally
            {
                processes[index].Dispose();
            }
        }

        FoundHandles.Clear();
        if (ProcessIds.Count == 0)
        {
            return new List<IntPtr>();
        }

        EnumWindows(WindowCallback, IntPtr.Zero);
        return new List<IntPtr>(FoundHandles);
    }

    private static bool OnWindow(IntPtr handle, IntPtr lParam)
    {
        uint processId;
        GetWindowThreadProcessId(handle, out processId);
        if (!ContainsProcessId((int)processId) || !IsWindowVisible(handle))
        {
            return true;
        }

        FoundHandles.Add(handle);
        return true;
    }

    private static bool ContainsProcessId(int processId)
    {
        for (int index = 0; index < ProcessIds.Count; index++)
        {
            if (ProcessIds[index] == processId)
            {
                return true;
            }
        }

        return false;
    }

    private delegate bool EnumWindowsProc(IntPtr handle, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr handle, out uint processId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr handle);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessage(IntPtr handle, uint message, IntPtr wParam, IntPtr lParam);
}
'@

If ($Null -Eq ([System.Management.Automation.PSTypeName]"CiscoBrowserCloser").Type) {
    Add-Type -TypeDefinition $CiscoBrowserSource -Language CSharp
}

$CiscoFailoverNoticeSource = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class CiscoFailoverNotice
{
    private const string NoticeMarker = "retry logging on with the service provider";
    private static bool FoundNotice;
    private static IntPtr OkButton;

    public static bool TryDismiss()
    {
        try
        {
            FoundNotice = false;
            OkButton = IntPtr.Zero;
            EnumWindows(OnWindow, IntPtr.Zero);
            if (!FoundNotice || OkButton == IntPtr.Zero)
            {
                return false;
            }

            PostMessage(OkButton, 0x00F5, IntPtr.Zero, IntPtr.Zero);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static bool OnWindow(IntPtr handle, IntPtr lParam)
    {
        if (!IsWindowVisible(handle))
        {
            return true;
        }

        FoundNotice = false;
        OkButton = IntPtr.Zero;
        EnumChildWindows(handle, OnChild, IntPtr.Zero);
        if (FoundNotice && OkButton != IntPtr.Zero)
        {
            return false;
        }

        FoundNotice = false;
        OkButton = IntPtr.Zero;
        return true;
    }

    private static bool OnChild(IntPtr handle, IntPtr lParam)
    {
        string text = ReadText(handle);
        if (text.IndexOf(NoticeMarker, StringComparison.OrdinalIgnoreCase) >= 0)
        {
            FoundNotice = true;
        }

        if (IsOkButton(text) && IsButton(handle))
        {
            OkButton = handle;
        }

        return true;
    }

    private static bool IsOkButton(string name)
    {
        if (name == null)
        {
            return false;
        }

        string trimmed = name.Replace("&", "").Trim();
        return string.Equals(trimmed, "OK", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsButton(IntPtr handle)
    {
        string className = ReadClassName(handle);
        if (string.Equals(className, "Button", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return className.IndexOf("BUTTON", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static string ReadText(IntPtr handle)
    {
        StringBuilder text = new StringBuilder(2048);
        GetWindowText(handle, text, text.Capacity);
        return text.ToString();
    }

    private static string ReadClassName(IntPtr handle)
    {
        StringBuilder text = new StringBuilder(256);
        GetClassName(handle, text, text.Capacity);
        return text.ToString();
    }

    private delegate bool EnumWindowsProc(IntPtr handle, IntPtr lParam);
    private delegate bool EnumChildProc(IntPtr handle, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumChildWindows(IntPtr parent, EnumChildProc callback, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr handle);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr handle, StringBuilder text, int maxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr handle, StringBuilder text, int maxCount);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessage(IntPtr handle, uint message, IntPtr wParam, IntPtr lParam);
}
'@

If ($Null -Eq ([System.Management.Automation.PSTypeName]"CiscoFailoverNotice").Type) {
    Add-Type -TypeDefinition $CiscoFailoverNoticeSource -Language CSharp
}

$NetworkChangeRelaySource = @'
using System;
using System.Net.NetworkInformation;
using System.Windows.Threading;

public static class NetworkChangeRelay
{
    private static bool IsListening;
    private static Dispatcher Dispatcher;
    private static Action Callback;

    public static void Start(Dispatcher dispatcher, Action callback)
    {
        Stop();
        Dispatcher = dispatcher;
        Callback = callback;
        NetworkChange.NetworkAddressChanged += OnAddressChanged;
        NetworkChange.NetworkAvailabilityChanged += OnAvailabilityChanged;
        IsListening = true;
    }

    public static void Stop()
    {
        if (!IsListening)
        {
            return;
        }

        NetworkChange.NetworkAddressChanged -= OnAddressChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnAvailabilityChanged;
        IsListening = false;
        Callback = null;
        Dispatcher = null;
    }

    private static void OnAddressChanged(object sender, EventArgs e)
    {
        Dispatch();
    }

    private static void OnAvailabilityChanged(object sender, NetworkAvailabilityEventArgs e)
    {
        Dispatch();
    }

    private static void Dispatch()
    {
        Dispatcher dispatcher = Dispatcher;
        Action callback = Callback;
        if (dispatcher == null || callback == null)
        {
            return;
        }

        dispatcher.BeginInvoke(callback);
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
            Write-Host "[WARN] Could not read the Wi-Fi network name."
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

Function Update-WifiStatus {
    Try {
        $Snapshot = [WifiMonitor]::Query()
        $Script:LinkState = [String]$Snapshot.State
        If ($Script:LinkState -Ne $Script:LastLoggedLinkState) {
            Write-SignInLog ("[INFO] Wi-Fi state is " + $Script:LinkState + ". " + [String]$Snapshot.Detail)
            $Script:LastLoggedLinkState = $Script:LinkState
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
            Set-WifiStatusAppearance -Kind "Offline"
            $Script:StatusText.Text = "Not connected to Wi-Fi"
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
        $StatusError = [String]$Error[0]
        Write-SignInLog ("[ERROR] Wi-Fi status update failed: " + $StatusError)
        Throw
    }
}

Function Update-SignInButtonState {
    If ($Null -Eq $Script:OpenSignInButton) {
        Return
    }

    $WifiConnected = $Script:LinkState -Eq "Connected"
    $SignInBusy = $Script:IsOpening -Eq $True
    $Script:OpenSignInButton.IsEnabled = ($WifiConnected -Eq $True) -And ($SignInBusy -Eq $False)
}

Function Start-SignInBrowser {
    $EdgeCandidates = @(
        (Join-Path $Env:ProgramFiles "Microsoft\Edge\Application\msedge.exe")
    )
    $ProgramFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    If ([String]::IsNullOrWhiteSpace($ProgramFilesX86) -Eq $False) {
        $EdgeCandidates += (Join-Path $ProgramFilesX86 "Microsoft\Edge\Application\msedge.exe")
    }

    ForEach ($EdgePath in $EdgeCandidates) {
        If (Test-Path -LiteralPath $EdgePath) {
            Start-Process -FilePath $EdgePath -ArgumentList $Script:TriggerUrl
            Return "Edge"
        }
    }

    Start-Process -FilePath $Script:TriggerUrl
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
            Write-SignInLog ("[WARN] Could not open Wi-Fi settings: " + [String]$Error[0])
        }
    }
}

Function Get-SignInResultMessage {
    Param(
        [String]$CiscoState,
        [String]$Browser
    )

    $Lead = "Launching the authentication page in your default browser."
    If ($Browser -Eq "Edge") {
        $Lead = "Launching the authentication page in Microsoft Edge."
    }
    If ($CiscoState -Eq "StillOpen") {
        $Lead = $Lead + " If the sign-in page does not appear, try again."
    }

    If ($Script:LinkState -Eq "RadioOff") {
        Return ($Lead + " Turn Wi-Fi on to load the sign-in page.")
    }

    If ($Script:LinkState -Eq "Disconnected") {
        Return ($Lead + " Connect to a Wi-Fi network to load the sign-in page.")
    }

    Return $Lead
}

Function Complete-SignInLaunch {
    Param(
        [String]$CiscoState
    )

    Try {
        $Browser = Start-SignInBrowser
        $Message = Get-SignInResultMessage -CiscoState $CiscoState -Browser $Browser
        $Brush = $Script:SuccessTextBrush
        If (($CiscoState -Eq "StillOpen") -Or ($Browser -Ne "Edge") -Or ($Script:LinkState -Eq "RadioOff") -Or ($Script:LinkState -Eq "Disconnected")) {
            $Brush = $Script:WarningTextBrush
        }

        If (($CiscoState -Eq "StillOpen") -Or ($Browser -Ne "Edge") -Or ($Script:LinkState -Eq "RadioOff") -Or ($Script:LinkState -Eq "Disconnected")) {
            Show-ActionResult -Message $Message -Foreground $Brush
        }
        Else {
            $Script:ResultText.Visibility = [System.Windows.Visibility]::Collapsed
        }
    }
    Catch {
        $OpenError = $Error[0].Exception.Message
        Show-ActionResult -Message ("Could not open Microsoft Edge. " + $OpenError) -Foreground $Script:ErrorTextBrush
    }
    Finally {
        $Script:Cooldown = New-Object System.Windows.Threading.DispatcherTimer
        $Script:Cooldown.Interval = [TimeSpan]::FromSeconds(1)
        $Script:Cooldown.Add_Tick({
            $Script:Cooldown.Stop()
            $Script:IsOpening = $False
            Update-SignInButtonState
        })
        $Script:Cooldown.Start()
    }
}

Function Complete-SignInAfterCiscoClose {
    If ($Script:CiscoCloseFinished -Eq $True) {
        Return
    }

    $StillOpen = [CiscoBrowserCloser]::HasVisibleWindow()
    $TimedOut = (Get-Date) -Gt $Script:CiscoCloseDeadline
    If (($StillOpen -Eq $True) -And ($TimedOut -Eq $False)) {
        Return
    }

    $Script:CiscoCloseFinished = $True
    If ($Script:CiscoCloseTimer -Ne $Null) {
        $Script:CiscoCloseTimer.Stop()
    }

    $CiscoState = "StillOpen"
    If ($StillOpen -Eq $False) {
        $CiscoState = "Closed"
    }

    Complete-SignInLaunch -CiscoState $CiscoState
}

Function Invoke-SignInPage {
    If ($Script:IsOpening -Eq $True) {
        Return
    }

    $Script:IsOpening = $True
    $Script:OpenSignInButton.IsEnabled = $False
    Write-SignInLog "[INFO] Open sign-in page clicked."
    Start-FailoverNoticeMonitor
    $CloseRequests = [CiscoBrowserCloser]::RequestClose()
    Write-SignInLog ("[INFO] Cisco browser close requests=" + $CloseRequests)
    If ($CloseRequests -Gt 0) {
        Show-ActionResult -Message "Opening the sign-in page..." -Foreground $Script:WarningTextBrush
        $Script:CiscoCloseFinished = $False
        $Script:CiscoCloseDeadline = (Get-Date).AddSeconds(2)
        $Script:CiscoCloseTimer = New-Object System.Windows.Threading.DispatcherTimer
        $Script:CiscoCloseTimer.Interval = [TimeSpan]::FromMilliseconds(100)
        $Script:CiscoCloseTimer.Add_Tick({ Complete-SignInAfterCiscoClose })
        $Script:CiscoCloseTimer.Start()
        Return
    }

    Complete-SignInLaunch -CiscoState "None"
}

Function Move-SignInWindowToTopRight {
    $Script:Window.UpdateLayout()
    $WindowWidth = $Script:Window.ActualWidth
    $WindowHeight = $Script:Window.ActualHeight
    If ($WindowWidth -Le 0) {
        $WindowWidth = $Script:Window.Width
    }
    If ($WindowHeight -Le 0) {
        $WindowHeight = 240
    }

    $WorkArea = [System.Windows.SystemParameters]::WorkArea
    $EdgeGap = 16
    $ShadowMargin = 14
    $Script:Window.Left = $WorkArea.Right - $WindowWidth - $EdgeGap + $ShadowMargin
    $Script:Window.Top = $WorkArea.Top + $EdgeGap - $ShadowMargin
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
    If ($Script:FailoverNoticeTimer -Ne $Null) {
        $Script:FailoverNoticeTimer.Stop()
    }

    $Script:FailoverNoticeDeadline = (Get-Date).AddSeconds(5)
    $Script:FailoverNoticeTimer = New-Object System.Windows.Threading.DispatcherTimer
    $Script:FailoverNoticeTimer.Interval = [TimeSpan]::FromMilliseconds(250)
    $Script:FailoverNoticeTimer.Add_Tick({ Update-FailoverNoticeMonitor })
    $Script:FailoverNoticeTimer.Start()
    Write-SignInLog "[INFO] Watching for the Cisco failover notice for 5 seconds."
}

Function Update-FailoverNoticeMonitor {
    Try {
        If ((Get-Date) -Gt $Script:FailoverNoticeDeadline) {
            $Script:FailoverNoticeTimer.Stop()
            Write-SignInLog "[INFO] Cisco failover notice was not shown. Monitor stopped."
            Return
        }

        If ([CiscoFailoverNotice]::TryDismiss() -Eq $True) {
            $Script:FailoverNoticeTimer.Stop()
            Write-SignInLog "[INFO] Cisco failover notice was dismissed."
        }
    }
    Catch {
        If ($Script:FailoverNoticeTimer -Ne $Null) {
            $Script:FailoverNoticeTimer.Stop()
        }

        Write-SignInLog ("[ERROR] Cisco failover notice monitor failed: " + [String]$Error[0])
    }
}

Function Close-SignInWindow {
    If ($Script:Timer -Ne $Null) {
        $Script:Timer.Stop()
    }

    If ($Script:CiscoCloseTimer -Ne $Null) {
        $Script:CiscoCloseTimer.Stop()
    }

    If ($Null -Ne ([System.Management.Automation.PSTypeName]"NetworkChangeRelay").Type) {
        [NetworkChangeRelay]::Stop()
    }

    If ($Script:FailoverNoticeTimer -Ne $Null) {
        $Script:FailoverNoticeTimer.Stop()
    }
}

Function Set-WindowArtwork {
    $AssetFolder = Join-Path (Split-Path -Parent $PSCommandPath) "Assets"
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
            Write-SignInLog ("[WARN] App icon could not be loaded: " + [String]$Error[0])
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
            $HeaderBanner.Source = $HeaderImage
        }
    }
    Catch {
        Write-SignInLog ("[WARN] Header banner could not be loaded: " + [String]$Error[0])
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
                <RowDefinition Height="Auto" />
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

            <StackPanel Grid.Row="2" Margin="12,16,12,18">
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
            Write-SignInLog ("[WARN] Window drag did not start: " + [String]$Error[0])
        }
    }
})
$Script:Window.Add_SizeChanged({ Update-WindowCornerClip })
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
$Script:Window.Add_Activated({ Update-WifiStatus })
$Script:Window.Add_Closed({
    Write-SignInLog "[INFO] Sign-in window Closed event."
    Close-SignInWindow
})
$Script:Window.Dispatcher.Add_UnhandledException({
    Param($Sender, $EventArgs)
    $ExceptionText = ""
    If ($Null -Ne $EventArgs.Exception) {
        $ExceptionText = $EventArgs.Exception.ToString()
    }
    Write-SignInLog ("[ERROR] Dispatcher unhandled exception: " + $ExceptionText)
})
$Script:Window.Dispatcher.Add_ShutdownStarted({
    Write-SignInLog "[INFO] Dispatcher shutdown started."
})

$Script:Timer = New-Object System.Windows.Threading.DispatcherTimer
$Script:Timer.Interval = [TimeSpan]::FromSeconds(2)
$Script:Timer.Add_Tick({ Update-WifiStatus })

$Script:OnNetworkChanged = {
    Write-SignInLog "[INFO] Network change notification."
    Update-WifiStatus
}
[NetworkChangeRelay]::Start($Script:Window.Dispatcher, [System.Action]$Script:OnNetworkChanged)

Write-SignInLog "[INFO] Opening the captive portal sign-in window."
Write-Host "[INFO] Opening the captive portal sign-in window."
Try {
    $Script:Window.ShowDialog() | Out-Null
    Write-SignInLog "[INFO] ShowDialog returned."
}
Catch {
    $DialogError = [String]$Error[0]
    Write-SignInLog ("[ERROR] ShowDialog ended with an error: " + $DialogError)
    Write-Error "[ERROR] ShowDialog ended with an error: $DialogError"
}
Write-SignInLog "[INFO] Sign-in script is exiting."
Write-Host "[INFO] Captive portal sign-in window closed."
Exit 0
