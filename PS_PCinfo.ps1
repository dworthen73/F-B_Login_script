
# +------------------------------------------------------+
# | Computer Mentors System Information V3.0             |
# | Code adapted from:                                   |
# |          Powershell PC Info Script V1.0b             | 
# |             Coded By:Trenton Ivey(kno)               | 
# |                    hackyeah.com                      | 
# +------------------------------------------------------+
$ErrorActionPreference = 'silentlycontinue'

$name = "$env:username"
$strFilter = “(&(objectCategory=User)(SAMAccountName=$Env:USERNAME))”
 $objDomain = New-Object System.DirectoryServices.DirectoryEntry
 $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
 $objSearcher.SearchRoot = $objDomain
 $objSearcher.PageSize = 1
 $objSearcher.Filter = $strFilter
 $objSearcher.SearchScope = “Subtree”
 $colProplist = "sn","givenname","samaccountname","displayname","postofficebox","mail","roomnumber","telephonenumber","name","physicaldeliveryofficename","generationQualifier" ,"street" , "buildingName"
    foreach ($i in $colPropList){$null = $objSearcher.PropertiesToLoad.Add($i)}
    
 $colResults = $objSearcher.FindAll()
 
 $FileName = $colResults[0].Properties.name
 
#$SDC = (Get-ItemProperty "hklm:\SOFTWARE\USAF\SDC\ImageRev").CurrentBuild
$SDC = cmd /c ver

$SDCDT = Get-ItemProperty "hklm:\SYSTEM\SETUP"
$SDCRD = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId

$compname = $env:computername

$logonServer = "$env:LOGONSERVER"

Function ShowInfo { 

"SDC Date            : " + $SDCDT.CloneTag 
"SDC Version         :" + $SDC
"SDC Release         : " + $SDCRD
"Name                : " + $colResults[0].Properties.displayname
"Office              : " + $colResults[0].Properties.physicaldeliveryofficename
"Email               : " + $colResults[0].Properties.mail
"Cube                : " + $colResults[0].Properties.roomnumber
"Phone               : " + $colResults[0].Properties.telephonenumber
"Street              : " + $colResults[0].Properties.street
"buildingName        : " + $colResults[0].Properties.buildingName
"Logon Server        : " + $logonServer

# Create Table
       $CITable = New-Object system.Data.DataTable "Computer Information"
#Create Columns for table 
       $CITcol1 = New-Object system.Data.DataColumn Item,([string])       
       $CITcol2 = New-Object system.Data.DataColumn Value,([string])
#Add Columns to table
       $CITable.columns.add($CITcol1)
       $CITable.columns.add($CITcol2)
$I = gwmi -computer $compname Win32_ComputerSystem    
#Create Row Variable 
      $CITRow = $CITable.NewRow()
#Assign items to row variable
      $CITRow.Item = 'Computer Name' 
      $CITRow.Value = $I.Name
#Add Row to Table using Row Variable
      $CITable.Rows.Add($CITRow)
      
      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'Domain Name'
      $CITRow.Value = $I.Domain
      $CITable.Rows.Add($CITRow)
      
      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'Manufacturer'
      $CITRow.Value = $I.Manufacturer
      $CITable.Rows.Add($CITRow)
      
      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'Model'
      $CITRow.Value = $I.Model
      $CITable.Rows.Add($CITRow)
      
      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'System Type'
      $CITRow.Value = $I.SystemType
      $CITable.Rows.Add($CITRow)
      $CITRow = $CITable.NewRow()

$SDC.CurrentBuild     
      
$I = gwmi -computer $compname Win32_BIOS

      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'BIOS Name'
      $CITRow.Value = $I.Name
      $CITable.Rows.Add($CITRow)
      
      $CITRow = $CITable.NewRow()
      $CITRow.Item = '  Version'
      $CITRow.Value = $I.SMBIOSBIOSVersion
      $CITable.Rows.Add($CITRow)
      
$I = gwmi -computer $compname Win32_ComputerSystem

      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'Current User ID'
      $CITRow.Value = $I.Username
      $CITable.Rows.Add($CITRow)
      
$I = gwmi -computer $compname Win32_OperatingSystem
      
      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'OS Name'
      $CITRow.Value = $I.Caption
      $CITable.Rows.Add($CITRow)
      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'Service Pack'
      $CITRow.Value = $I.ServicePackMajorVersion
      $CITable.Rows.Add($CITRow)
      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'OS Bit Width'
      $CITRow.Value = $I.OSArchitecture
      $CITable.Rows.Add($CITRow)
      
$I = gwmi -computer $compname Win32_Processor
      
      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'Processor Name'
      $CITRow.Value = $I.Name
      $CITable.Rows.Add($CITRow)
      $CITRow = $CITable.NewRow()
      $CITRow.Item = '          Info'
      $CITRow.Value = $I.Caption
      $CITable.Rows.Add($CITRow)
      $CITRow = $CITable.NewRow()
      $CITRow.Item = '          Cores'
      $CITRow.Value = $I.NumberofCores
      $CITable.Rows.Add($CITRow)
      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'Address Width'
      $CITRow.Value = $I.AddressWidth
      $CITable.Rows.Add($CITRow)
 
$wmi = gwmi -computer $compname Win32_OperatingSystem
 
      $localdatetime = $wmi.ConvertToDateTime($wmi.LocalDateTime) 
      $lastbootuptime = $wmi.ConvertToDateTime($wmi.LastBootUpTime) 
      
      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'Time Current'
      $CITRow.Value = $LocalDateTime
      $CITable.Rows.Add($CITRow)
      
      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'Last Boot'
      $CITRow.Value = $LastBootUpTime
      $CITable.Rows.Add($CITRow)
      
      $CITRow = $CITable.NewRow()
      $CITRow.Item = 'Total Up Time'
      $CITRow.Value = $localdatetime - $lastbootuptime
      $CITable.Rows.Add($CITRow)
      
#Output table
      $fmt = @{Expression={$_.Item};Label="Item";width=20},
             @{Expression={$_.Value};Label="Value";Width=40}
             
      $CITable | Select-Object Item,Value | Format-Table $fmt

function Convert-BytesToString($bytes) {
  $result = ""
  for ( $n = 0; $n -lt $bytes.Length; $n++ ) {
    if ( $bytes[$n] -ne 0 ) {
      $result += [Char] $bytes[$n]
    }
    else {
      break
    }
  }
  $result
}

"Monitors"

 $Monitors = Get-WmiObject -Class "WmiMonitorID" -Namespace "root\wmi" | Where  {$_ -ne "0"} 

 foreach ( $monitor in $monitors ) {

   $man = Convert-BytesToString $monitor.ManufacturerName
   $Product = Convert-BytesToString $monitor.ProductCodeID
   $Ser = Convert-BytesToString $monitor.SerialNumberID
   $UserFriendlyName = Convert-BytesToString $monitor.UserFriendlyName
   
 ""
   "$man `t $Product `t $Ser `t $UserFriendlyName"  
   }
   ""
   "Network Adapter Information:"
""
 $colItems = get-wmiobject -class "Win32_NetworkAdapterConfiguration"  -namespace "root\CIMV2" -computername $compname
 foreach ($objItem in $colItems)
 {
 # A test is needed here as the loop will find a number of virtual network configurations with no  "Hostname" 
 # So if the "Hostname" does not exist, do NOT display it!
  if ($objItem.DNSHostName -ne $NULL) 
  {
  $ObjItem.Description
  $objItem.IPAddress
  $ObjItem.MACAddress
  }
  }
    ""  
#Disk Info               
            $fmt = @{Expression={$_.Name};Label="Drive Letter";width=12},
                   @{Expression={$_.ProviderName};Label="Path";Width=100}
                                          
            $wmi = gwmi -computer $compname Win32_logicaldisk 
            $wmi | Format-Table $fmt
            
"AD Group Membership:"
""
([ADSISEARCHER]"samaccountname=$($NAME)").Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1'

""
"generationQualifier : " + $colResults[0].Properties.generationQualifier

""
###################   Looks for Attatched PST Files   ####
"Outlook Checked"
""
$Outlook = New-Object -ComObject Outlook.Application
$stores = $Outlook.Session.Stores
$stores | Where-Object { $_.FilePath -like '*.pst' } | %{$_.FilePath}

###################   Looks to see if OneDrive is Installed   ####
""

If ($env:OneDrive)
{ "OneDrive:`t User has OneDrive Installed"}
Else {"OneDrive:`t OneDrive Not Installed" }
""
$Status = Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\BitlockerStatus -Name "BootStatus"
    If($Status -eq "0"){"BitLocker:           Off"}
    If($Status -eq "1"){"BitLocker:           ON"}

} #End Function ShowInfo
 
#---------Start Main-------------- 
Clear-Host
ShowInfo | Out-File -FilePath "\\zhtv-fs-610v\AFLCMC_WL_1\Groups\IT\cycfs001\Scripts\User_Info\Detailed\$FileName.txt" 
ShowInfo | out-host

Exit