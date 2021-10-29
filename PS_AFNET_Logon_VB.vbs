'On Error Resume Next

Dim objShell,F2,FS,fso,fso1,S,objShellP

Const OKbox = 0
Const wshMark = 64
Source = "\\zhtv-fs-610v\AFLCMC_WL_1\Groups\IT\cycfs001\Scripts\LogonScripts"
Destination = "C:\logon"

'check to see if we are local admin and if so exit \
Set oShell = CreateObject( "WScript.Shell" ) 
usersName =  oShell.ExpandEnvironmentStrings("%UserName%")
if lcase(usersName) = "usaf_admin" then wscript.quit


'Copy the login files to a local folder so powershell will run without prompts 
Set FS=CreateObject("Scripting.FileSystemObject")
If FS.FolderExists(Destination) Then
else
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set f = fso.CreateFolder(Destination)
    CreateFolderDemo = f.Path
end if

Set S=CreateObject("Scripting.FileSystemObject")

If S.FolderExists(Source) Then
    Set fso1 = CreateObject("Scripting.FileSystemObject")
    For Each R In S.GetFolder(Source).Files
        Set f2 = fso1.GetFile(r.path)
        f2.copy (destination & "\" & r.name)
    Next
else

end if
Set objShell = WScript.CreateObject("WScript.Shell")

    command =  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nologo -command ""C:\logon\PS_MapDrives_Mobility-Net-Use.ps1"""
	set shell = CreateObject("WScript.Shell")
 		shell.Run command,0
 
wscript.sleep 300000
command2 = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nologo -command ""C:\logon\PS_Logon_Script.ps1"""
	set shell = CreateObject("WScript.Shell")
 		shell.Run command2,0

wscript.sleep 30000
command3 = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nologo -command ""C:\logon\Script-Loop.ps1"""
	set shell = CreateObject("WScript.Shell")
 		shell.Run command3,0
wscript.quit
