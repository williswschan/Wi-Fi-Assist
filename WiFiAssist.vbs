Option Explicit

Dim Shell, FileSystem, ScriptFolder, ScriptPath, PowerShell, Command, LaunchError

Set Shell = CreateObject("WScript.Shell")
Set FileSystem = CreateObject("Scripting.FileSystemObject")
ScriptFolder = FileSystem.GetParentFolderName(WScript.ScriptFullName)
ScriptPath = FileSystem.BuildPath(ScriptFolder, "WiFiAssist.ps1")
PowerShell = Shell.ExpandEnvironmentStrings("%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe")

If FileSystem.FileExists(ScriptPath) = False Then
    MsgBox "WiFiAssist.ps1 was not found next to this file.", vbCritical, "Wi-Fi Assist"
    WScript.Quit 1
End If

If FileSystem.FileExists(PowerShell) = False Then
    MsgBox "Windows PowerShell was not found. Contact your support team.", vbCritical, "Wi-Fi Assist"
    WScript.Quit 1
End If

Command = """" & PowerShell & """ -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & ScriptPath & """ -StaHost"
On Error Resume Next
Shell.Run Command, 0, False
LaunchError = Err.Number
On Error GoTo 0
If LaunchError <> 0 Then
    MsgBox "Wi-Fi Assist could not start Windows PowerShell. Error " & CStr(LaunchError) & ". Contact your support team.", vbCritical, "Wi-Fi Assist"
    WScript.Quit 1
End If
