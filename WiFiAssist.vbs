Option Explicit

Dim Shell, FileSystem, ScriptFolder, ScriptPath, PowerShell, Command

Set Shell = CreateObject("WScript.Shell")
Set FileSystem = CreateObject("Scripting.FileSystemObject")
ScriptFolder = FileSystem.GetParentFolderName(WScript.ScriptFullName)
ScriptPath = FileSystem.BuildPath(ScriptFolder, "WiFiAssist.ps1")
PowerShell = Shell.ExpandEnvironmentStrings("%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe")

If FileSystem.FileExists(ScriptPath) = False Then
    MsgBox "WiFiAssist.ps1 was not found next to this file.", vbCritical, "Wi-Fi Assist"
    WScript.Quit 1
End If

Command = """" & PowerShell & """ -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & ScriptPath & """"
Shell.Run Command, 0, False
