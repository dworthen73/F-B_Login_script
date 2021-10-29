#Logon script for WA&WB 


#I want the logon script to call forth 3 ps scripts 


#Source = "\\zhtv-fs-611v\AFLCMC_WA__WB_1\Groups\FASW.APPS\INSTALLS\Drive Mapping\LogonScripts"
#Destination = "C:\logon"

#this is the vbs script from WL that I want PS to mimic
#'Copy the login files to a local folder so powershell will run without prompts 
##Set FS=CreateObject("Scripting.FileSystemObject")
#If FS.FolderExists(Destination) Then
#else
  #  Set fso = CreateObject("Scripting.FileSystemObject")
  #  Set f = fso.CreateFolder(Destination)
   # CreateFolderDemo = f.Path
#end if



