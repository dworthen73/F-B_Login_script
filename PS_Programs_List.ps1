

[cmdletbinding()]            
param(            
 [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]            
 [string[]]$ComputerName = $env:computername            
)            
            
begin {       
if (test-path "\\zhtv-fs-610v\AFLCMC_WL_1\Groups\IT\cycfs001\Scripts\User_Info\Installed_Programs\$ComputerName.csv"){Remove-Item "\\zhtv-fs-610v\AFLCMC_WL_1\Groups\IT\cycfs001\Scripts\User_Info\Installed_Programs\$ComputerName.csv"}
     
 $UninstallRegKeys=@("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",            
     "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")            
}            
            
process {            
 <#foreach($Computer in $ComputerName) {            
  Write-Verbose "Working on $Computer"            
 if(Test-Connection -ComputerName $Computer -Count 1 -ea 0) {  #>          
  foreach($UninstallRegKey in $UninstallRegKeys) {            
   try {            
    $HKLM   = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computer)            
    $UninstallRef  = $HKLM.OpenSubKey($UninstallRegKey)            
    $Applications = $UninstallRef.GetSubKeyNames()            
   } catch {            
    Write-Verbose "Failed to read $UninstallRegKey"            
    Continue            
   }            
            
   foreach ($App in $Applications) {            
   $AppRegistryKey  = $UninstallRegKey + "\\" + $App            
   $AppDetails   = $HKLM.OpenSubKey($AppRegistryKey)            
   $AppGUID   = $App            
   $AppDisplayName  = $($AppDetails.GetValue("DisplayName"))            
   $AppVersion   = $($AppDetails.GetValue("DisplayVersion"))            
   $AppPublisher  = $($AppDetails.GetValue("Publisher"))            
   $AppInstalledDate = $($AppDetails.GetValue("InstallDate"))            
   $AppUninstall  = $($AppDetails.GetValue("UninstallString"))            
   if($UninstallRegKey -match "Wow6432Node") {            
    $Softwarearchitecture = "x86"            
   } else {            
    $Softwarearchitecture = "x64"            
   }            
   if(!$AppDisplayName) { continue }            
   $OutputObj = New-Object -TypeName PSobject             
   $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $env:computername.ToUpper()             
   $OutputObj | Add-Member -MemberType NoteProperty -Name AppName -Value $AppDisplayName            
   $OutputObj | Add-Member -MemberType NoteProperty -Name AppVersion -Value $AppVersion            
   $OutputObj | Add-Member -MemberType NoteProperty -Name AppVendor -Value $AppPublisher            
   #$OutputObj | Add-Member -MemberType NoteProperty -Name InstalledDate -Value $AppInstalledDate            
   $OutputObj | Add-Member -MemberType NoteProperty -Name UninstallKey -Value $AppUninstall            
   #$OutputObj | Add-Member -MemberType NoteProperty -Name AppGUID -Value $AppGUID            
   #$OutputObj | Add-Member -MemberType NoteProperty -Name SoftwareArchitecture -Value $Softwarearchitecture            
   #$OutputObj | Where {$_.AppName -notlike "*Update*"} | Export-csv \\zhtv-fs-610v\AFLCMC_WL_1\Groups\IT\cycfs001\Scripts\User_Info\Installed_Programs\$ComputerName.csv -append
   $OutputObj | Export-csv \\zhtv-fs-610v\AFLCMC_WL_1\Groups\IT\cycfs001\Scripts\User_Info\Installed_Programs\$ComputerName.csv -append
      #$OutputObj.AppName | Where { $_ -notlike "*Update*" } | Export-csv c:\temp\

   }            
  }             
 }            
 
 end {}

<#Get-InstalledSoftware.ps1 -ComputerName (Get-Content D:\U\Desktop\test.txt)| out-file D:\U\Desktop\computers1.txt

Get-InstalledSoftware.ps1 -ComputerName PC1 | ? {$_.AppVendor -NotMatch “Microsoft” }

Get-Content C:\Test\computers.txt | .\Get-InstallSoftware.ps1 | ft -auto

.\Get-InstalledSoftware.ps1 -ComputerName Computer1| Where {$_.InstallDate -gt “20140101″}

.\Get-InstalledSoftware.ps1 -ComputerName ZHTVL-390KDP | ? {$_.AppName -eq “IBM Forms Viewer 4.0.0” } | .\Uninstall-InstalledSoftware2.ps1

.\Get-InstalledSoftware.ps1 -ComputerName ZHTVL-390CXR | ? {$_.AppGUID -eq “48462CC7-7DF3-4107-9459-12D3A11C6D80” } | .\Uninstall-InstalledSoftware2.ps1

.\Uninstall-InstalledSoftware2.ps1 -ComputerName ZHTVL-390CXR

#IBM Forms Viewer 4.0.0

{48462CC7-7DF3-4107-9459-12D3A11C6D80}


.\softwarelist.ps1 -ComputerName zhtvl-390cjj | ? {$_.AppName -Like “*KB26*” }

.\Get-InstalledSoftware.ps1 -ComputerName ZHTVW-502094 | ? {$_.AppName -Like “*kb4018351*” }



#>