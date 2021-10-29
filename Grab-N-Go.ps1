<#
    Grab & Go
    Author:  PATTERSON, MICHAEL A GS-12 USAF AFMC 88 CS/SCOSC
    Initial version 17-Jun-2020

    CHANGE HISTORY:
    Version 2.5   - 6/25/2020
                    - Bugfix:  Fixed filenames/paths containing spaces
                    - Bugfix:  Check for AD Module first, if not available, will not run the remote GPUpdate
                    - Bugfix:  IP Address will release correctly now
                     - Bugfix:  Will continue to the next system in the list when encountering a failed system
                    - Will not waste time copying installers if they're already installed
                    - Checks for orphan status (not in a _Workstation group, or in more than one)

    Version 2.6   - 2/22/2021
                    - Consolidated single-use and remote Grab & Go into one script instead of two
                    - Added check for drivers that are in an error state

    Version 2.61  - 4/7/2021
                    - Updated to reflect newest vESD
                    - Bugfix where ActiveClient wasn't being properly detected

    Version 2.62  - 4/18/2021
                    - Updated file/folder paths to reflect SAN Share migration from 52ZHTV-FS-601v to ZHTV-FS-601V

    Version 2.63  - 7/1/2021
                    - Updated method of adding three scan groups to local-machine Administrators group
                      Should result in less errors, if any

    Version 2.64  - 7/9/2021
                    - Updated Driver checker to ignore PS2 KB/Mouse error 24 since they're rarely connected
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>

Param([string] $FileName,
      [string] $ComputerName = $ENV:ComputerName
     )  

# Local (Master) Logging function
    function LogLocal($string)
    {
        if (Test-Path $RemoteG2Log -ErrorAction SilentlyContinue)
        {
            $string | out-file -Filepath $RemoteG2Log -append -ErrorAction SilentlyContinue
        }
    }

# Log on Remote PC Function
function LogRemote($string)
    {
        $string | out-file -Filepath \\$PC\$logfile -append -ErrorAction SilentlyContinue
    }

# Log on Both Remote and Local PC
    function LogBoth($string)
    {
        # Log to local PC log (the remote overall log)
        if (Test-Path $RemoteG2Log -ErrorAction SilentlyContinue)
        {
            $string | out-file -Filepath $RemoteG2Log -append -ErrorAction SilentlyContinue
        }
        # Log to the remote PC's Grab & Go Log
        $string | out-file -Filepath \\$PC\$logfile -append -ErrorAction SilentlyContinue
    }

# Function to detect desktop versus laptop/tablet
    function DeskTop([string]$pcType) {
        if ($systemType -eq "2") {
            return $false       
        }
        else
        { 
            return $true
        }
    }

# Function to check if folder copy succeeded
    function CopyCheck($TargetFolder)
    {
        if (Test-Path $TargetFolder)
        {
            Write-Host "Successful" -ForegroundColor Green
            $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - $TargetFolder copied successfully" ; LogBoth $Text
        }
        else
        {
            Write-Host "Failed" -ForegroundColor Red
            $ErrorTally++
            $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - $TargetFolder failed to copy" ; LogBoth $Text
        }
    }

# Function to check if group is in local-administrators group
    function IsGroupAdmin($TargetObject)
    {
        $objGroup = [ADSI](“WinNT://$PC/Administrators”)
        $members = @($objGroup.psbase.Invoke(“Members”))
        $IsAdmin = $false
        $ErrorActionPreference = "SilentlyContinue"
        $members | foreach { $member = $_.GetType().InvokeMember(“Name”, ‘GetProperty’, $null, $_, $null); if ($member.Equals($TargetObject)) { $IsAdmin = $true } } 
        $ErrorActionPreference = "Continue"
        Return $IsAdmin
    }

function Get-InstalledSoftware {
    <#
	.SYNOPSIS
		Retrieves a list of all software installed on a Windows computer.
	.EXAMPLE
		PS> Get-InstalledSoftware
		
		This example retrieves all software installed on the local computer.
	.PARAMETER ComputerName
		If querying a remote computer, use the computer name here.
	
	.PARAMETER Name
		The software title you'd like to limit the query to.
	
	.PARAMETER Guid
		The software GUID you'e like to limit the query to
	#>
    [CmdletBinding()]
    param (
		
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME,
		
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
		
        [Parameter()]
        [guid]$Guid
    )
    process {
        try {
            $scriptBlock = {
                $args[0].GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value }
				
                $UninstallKeys = @(
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                )
                New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
                $UninstallKeys += Get-ChildItem HKU: | where { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | foreach {
                    "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
                }
                if (-not $UninstallKeys) {
                    Write-Warning -Message 'No software registry keys found'
                } else {
                    foreach ($UninstallKey in $UninstallKeys) {
                        $friendlyNames = @{
                            'DisplayName'    = 'Name'
                            'DisplayVersion' = 'Version'
                        }
                        Write-Verbose -Message "Checking uninstall key [$($UninstallKey)]"
                        if ($Name) {
                            $WhereBlock = { $_.GetValue('DisplayName') -like "$Name*" }
                        } elseif ($GUID) {
                            $WhereBlock = { $_.PsChildName -eq $Guid.Guid }
                        } else {
                            $WhereBlock = { $_.GetValue('DisplayName') }
                        }
                        $SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | Where-Object $WhereBlock
                        if (-not $SwKeys) {
                            Write-Verbose -Message "No software keys in uninstall key $UninstallKey"
                        } else {
                            foreach ($SwKey in $SwKeys) {
                                $output = @{ }
                                foreach ($ValName in $SwKey.GetValueNames()) {
                                    if ($ValName -ne 'Version') {
                                        $output.InstallLocation = ''
                                        if ($ValName -eq 'InstallLocation' -and 
                                            ($SwKey.GetValue($ValName)) -and 
                                            (@('C:', 'C:\Windows', 'C:\Windows\System32', 'C:\Windows\SysWOW64') -notcontains $SwKey.GetValue($ValName).TrimEnd('\'))) {
                                            $output.InstallLocation = $SwKey.GetValue($ValName).TrimEnd('\')
                                        }
                                        [string]$ValData = $SwKey.GetValue($ValName)
                                        if ($friendlyNames[$ValName]) {
                                            $output[$friendlyNames[$ValName]] = $ValData.Trim() ## Some registry values have trailing spaces.
                                        } else {
                                            $output[$ValName] = $ValData.Trim() ## Some registry values trailing spaces
                                        }
                                    }
                                }
                                $output.GUID = ''
                                if ($SwKey.PSChildName -match '\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b') {
                                    $output.GUID = $SwKey.PSChildName
                                }
                                New-Object -TypeName PSObject -Prop $output
                            }
                        }
                    }
                }
            }
			
            if ($ComputerName -eq $env:COMPUTERNAME) {
                & $scriptBlock $PSBoundParameters
            } else {
                Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $PSBoundParameters
            }
        } catch {
            Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
}

# Function to detect Admin Rights
    function Test-IsAdmin {
        try {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
            return $principal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )
        } catch {
            throw "Failed to determine if the current user has elevated privileges. The error was: '{0}'." -f $_
        }
    }

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                                 BEGIN SCRIPT
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Declare Variables
    $Version = "2.64"
    $OfficialVersionLocation = "\\ZHTV-FS-601V\88CS\Groups\SDC\CST_Tools\Grab-N-Go"
    $OfficialVersionFile = "$OfficialVersionLocation\Grab-N-Go_Version.txt"
    $LatestOfficalVersion = Get-Content $OfficialVersionFile -TotalCount 1
    $logfile = "C$\Windows\Logs\GrabNGo.log" 
    $todaysdatetime = Get-Date
    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm"
    $RemoteG2Log = "C:\Temp\RemoteG2Log.log"
    $InstallFiles = "C$\_Installs"
    $LocalInstallFiles = "C:\_Installs"
    $LocalGroup  = "Administrators"
    $Apps = "\\ZHTV-FS-601V\88CS\Groups\Apps"
    $USMTLocation = "\\ZHTV-FS-601V\88CS\Groups\SDC\Additional_Items\USMT\USMT10"
    $Domain = $env:userdomain
    $EDIPI = $env:username
    $UserName = ([adsi]"WinNT://$Domain/$EDIPI,user").fullname
    $ErrorTally = 0
    $CredGuardError = 0
    $Counter = 0
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $Separator = '~' * 75
    $FinalReport = @()
    $Results  = [ordered]@{
               ComputerName = ''
               ErrorCount = ''
}
    $Counter = 1
    $UserName = $env:username
    $Banner = @"

    ________            ___.       ____      ________        
   /  _____/___________ \_ |__    /  _ \    /  _____/  ____  
  /   \  __\_  __ \__  \ | __ \   >  _ </\ /   \  ___ /  _ \ 
  \    \_\  \  | \// __ \| \_\ \ /  <_\ \/ \    \_\  (  (_) )
   \______  /__|  (____  /___  / \_____\ \  \______  /\____/ 
          \/           \/    \/         \/         \/       

                         Version $Version
"@
# End Variables

# Set up screen colors and display banner
    [console]::ForegroundColor = "Green"
    [console]::BackgroundColor = "Black"
    Clear-Host
    Write-Host $Separator -ForegroundColor White
    Write-Host $Banner -ForegroundColor Magenta
    Write-Host $Separator -ForegroundColor White

# Check to see if there's a newer version of Grab & Go
    if (Test-Path $OfficialVersionLocation -ErrorAction SilentlyContinue)
    {
        Write-Host -NoNewline "Checking Grab & Go Version..." -ForegroundColor Yellow
        if ($Version -eq $LatestOfficalVersion)
        {
            #Version matches
            Write-Host "Most current version detected!" -ForegroundColor Green
        }
        else
        {
            # Version mismatch
            Write-Host "Version mismatch!" -ForegroundColor Red
            Write-Host "  - Check to ensure you're running the most current version found at:" -ForegroundColor Red
            Write-Host "  - $OfficialVersionLocation" -ForegroundColor Red
            Write-Host "Opening official version location and aborting script" -ForegroundColor Red
            Invoke-Item $OfficialVersionLocation
            Pause
            Exit
        }
        Write-Host $Separator -ForegroundColor White
    }

# Check for admin rights and Self-elevate to Admin if possible
    if (!(Test-IsAdmin))
    {
        # We are not running "as Administrator" - so relaunch as administrator
        # Create a new process object that starts PowerShell
        Write-Host "Admin rights not detected - attempting self-elevate" -ForegroundColor Red

        $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    
        # Specify the current script path and name as a parameter
        $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    
        # Indicate that the process should be elevated
        $newProcess.Verb = "runas";
    
        # Start the new process
        [System.Diagnostics.Process]::Start($newProcess);
    
        # Exit from the current, unelevated, process
        exit
    }

# One last check to be sure
    if (!(Test-IsAdmin))
    {
        Write-Host "Admin rights not detected - attempt to self-elevate failed" -ForegroundColor Red
        Write-Host "Script will abort"
        Pause
        Exit
    }

# Create the Temp Folder if it isn't already there
    if (!(Test-Path C:\Temp))
    {
        New-Item -ItemType Directory -Force -path C:\Temp | Out-Null
    }

# Validate Parameters
    if ($FileName -ne "")
    {
        # Being run remotely, no need for ComputerName parameter
        $ComputerName = ""
    }

    if ($ComputerName -eq "" -AND $FileName -eq "")
    {
        # No computer name and file doesn't exist
        Write-Host "Script started with the following parameters:"
        Write-Host "Filename: $FileName"
        Write-Host "ComputerName:  $ComputerName"  
        Write-Host "-----------------------------------------------------------------------------------" -ForegroundColor Red
        Write-Host "Missing or bad parameter.  You must call this script with only one of the following parameters:"
        Write-Host "-FileName <path/file.txt>"
        Write-Host "-ComputerName <ComputerName>"
        Write-Host ""
        Write-Host "Examples:"
        Write-Host -NoNewline "RemoteG2C -ComputerName ZHTVL-ABCXYZ12 " -ForegroundColor Yellow
        Write-Host "(Will run Grab & Go on a single computer)"
        Write-Host -NoNewline "RemoteG2C -FileName C:\Temp\List.txt " -ForegroundColor Yellow
        Write-Host "(Will run Grab & Go on all the computers listed in C:\Temp\List.txt)"
        Write-Host "-----------------------------------------------------------------------------------" -ForegroundColor Red
        pause
        exit
    }

    if ($ComputerName -ne "" -AND $FileName -ne "")
    {
        # Both parameters have values.  There can be only one.
        Write-Host "You must call this script with only one of the following parameters, (You used both):"
        Write-Host "Filename: $FileName"
        Write-Host "ComputerName:  $ComputerName" 
        pause
        exit
    }

    # Only one Parameter exists, let's validate them to make sure they make sense
        if ($ComputerName -ne "")
        {
            # Computer Name was passed
            $PCList = $ComputerName
        }
        else
        {
            # Must be a file name, Let's get the list of PC's
            if (Test-Path $FileName)
            {
                $PCList = Get-Content $FileName    
            }
            else
            {
                Write-Host "Input file ($InputFile) not found.  Aborting." -ForegroundColor Red
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - List of computers not found.  Aborting" ; LogLocal $Text
                Pause
                Exit
            }

        }

# Initialize log file
    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Remote G2 Log file initialization" ; LogLocal $Text

#Check for read-access to APPS
    if (Test-Path $Apps\microsoft)
    {
        # Can see it
    }
    else
    {
        # Can't Access Apps Share
        Write-Host "Unable to access $Apps share.  Script will not work correctly and is aborting." -BackgroundColor Red -ForegroundColor White
        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Unable to access $Apps - Script Abort" ; LogLocal $Text
        Pause
        Exit
    }

# Check to make sure there is at least one PC Name
    if ($PCList.count -LT 1)
    {
        Write-Host "List of PC's is empty.  Aborting." -ForegroundColor Red
        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - List of computers not found.  Aborting" ; LogLocal $Text
        Pause
        Exit
    }

# Check for ADUC
    try
    {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        if (Test-Path $env:SystemRoot\system32\DSA.MSC)
        {
            $ADUCExist = $True
        }
        else
        {
            $ADUCExist = $False
        }
    }
    catch
    {
        Write-Host "ADUC not installed, GPUpdates will not be run on remote computer(s)" -ForegroundColor Red
    }

# Determine exit-action (i.e. do we want to release the IP and shutdown?)
    # Ask for a reboot
        Write-host "Do you want to release IP and shutdown the successfully completed PC's?" -ForegroundColor Yellow
        Write-Host -NoNewline "(Default: No) " -ForegroundColor Yellow
            $YesNo = Read-Host "(Y/N)"
            Switch ($YesNo) 
             { 
                Y {$FinalActionShutdown = $True} 
                N {$FinalActionShutdown = $False} 
                Default {$FinalActionShutdown = $False} 
             }
        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Final Action Shutdown choice:  $FinalActionShutdown" ; LogLocal $Text

# Log the PC Names
    $Text = "List of PC Names:" ; LogLocal $Text
    LogLocal $PCList
    LogLocal $Separator

# Loop through each PC
    $SystemCount = $PCList.count
    foreach ($PC in $PCList)
    {
        $ErrorTally = 0
        $DriverTally = 0
        Write-Host $Separator -ForegroundColor White
        LogLocal $Separator
        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm"
        Write-Host "$PC ($Counter of $SystemCount) - $TimeStamp" -ForegroundColor White
        LogLocal $PC
        
        # Test to see if the PC is reachable with ADM rights
            Write-Host -NoNewline " - Ping `t`t" -ForegroundColor Yellow
            if (Test-Connection $PC -Count 1 -Quiet)
            {
                Write-Host "Online" -ForegroundColor Green
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - $PC is online" ; LogLocal $Text
            }
            else
            {
                Write-Host "Offline, skipping" -ForegroundColor Red
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - $PC does not respond" ; LogLocal $Text
                $Counter++
                $ErrorTally++
                $Results.ComputerName = $PC
                $Results.ErrorCount = $ErrorTally

                $Info = New-Object -TypeName PSObject -Property $Results
                $FinalReport += $Info
                Continue
            }

            Write-Host -NoNewline " - ADM Rights `t`t" -ForegroundColor Yellow
            if (Test-Path "\\$PC\C$")
            {
                Write-Host "Good" -ForegroundColor Green
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Admin rights confirmed" ; LogLocal $Text
            }
            else
            {
                Write-Host "No ADM Rights, skipping" -ForegroundColor Red
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Unable to confirm admin rights" ; LogLocal $Text
                $Counter++
                $ErrorTally++
                $Results.ComputerName = $PC
                $Results.ErrorCount = $ErrorTally

                $Info = New-Object -TypeName PSObject -Property $Results
                $FinalReport += $Info
                Continue
            }

        # Remove existing log file on remote PC, if found
            if (Test-Path \\$PC\$logfile)
            {
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Removing existing log file from $PC" ; LogLocal $Text
                Remove-Item \\$PC\$logfile -Force | Out-Null
            }

        # Establish log file on remote computer
            $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Grab & Go started on $PC by $UserName from $env:ComputerName" ; LogRemote $Text
            $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Final Action Shutdown choice:  $FinalActionShutdown" ; LogRemote $Text

        # Set up folders on remote PC
            Write-Host -NoNewline " - Folder Setup `t" -ForegroundColor Yellow
            if (Test-Path "\\$PC\$InstallFiles")
            {
                # Folder exists, delete it 
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Removing existing install files folder" ; LogBoth $Text
                Remove-Item \\$PC\$InstallFiles -Force -Recurse
            }

            if (!(Test-Path "\\$PC\C$\Temp"))
            {
                # Folder does not exist, create it 
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Creating C:\Temp on remote PC" ; LogBoth $Text
                New-Item -ItemType Directory -Force -path \\$PC\C$\Temp | Out-Null
            }
            else
            {
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - C:\Temp already exists on remote PC" ; LogBoth $Text
            }

            
            # Create Folder for files
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Creating install files folder" ; LogBoth $Text
                New-Item -ItemType Directory -Force -path \\$PC\$InstallFiles | Out-Null

            # Trust, but verify
            if (Test-Path "\\$PC\$InstallFiles")
            {
                # Folder is present now, proceed
                Write-Host "Done" -ForegroundColor Green
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Created install files folder" ; LogBoth $Text
            }
            else
            {
                # Folder still not present, abort
                Write-Host "Failed, skipping" -ForegroundColor Red
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Unable to create install files folder, skipping this PC" ; LogBoth $Text
                Break
            }

        # Platform detection (desktop vs. mobile)
            Write-Host -NoNewline " - Platform: `t`t" -ForegroundColor Yellow

            $wmiObj = Get-WmiObject -ComputerName $PC -class Win32_computersystem
            $systemType = $wmiObj.PCSystemType
            $oDeskTop = DeskTop $systemType
            if ($oDeskTop)
            {
                # Desktop
                $Platform = "Desktop"
            }
            else
            {
                # Laptop/Tablet
                $Platform = "Mobile"
            }
            Write-Host $Platform -ForegroundColor Green
            $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Platform: $Platform" ; LogBoth $Text

        # Copy files to PC
            Write-Host " - Filecopy `t`t" -ForegroundColor Yellow

            # EURAM and JRSS VPN clients for Mobile Devices Only
                if ($Platform -EQ "Mobile")
                    {
                        Write-Host -NoNewline "   -- VPN Clients `t" -ForegroundColor Yellow
                        $appToMatch = '*BIG-IP Edge*'
                        $EURAM = Get-InstalledSoftware -ComputerName $PC -Name $appToMatch

                        $appToMatch = '*Cisco AnyConnect Secure Mobility*'
                        $JRSS = Get-InstalledSoftware -ComputerName $PC -Name $appToMatch
                    
                        if ($EURAM.name -ne $null -or $JRSS.name -ne $null)
                        {
                            # It's installed already
                            Write-Host "Skipped, already installed" -ForegroundColor Green
                            $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - VPN Copy Skipped, both already installed" ; LogBoth $Text
                        }
                        else
                        {
                            Copy-Item "$Apps\AFNET VPN" "\\$PC\$InstallFiles\LaptopLoad\AFNETVPN" -Recurse | Out-Null
                            CopyCheck "\\$PC\$InstallFiles\LaptopLoad\AFNETVPN"
                        }
                    }

            # NVSPBind
                Write-Host -NoNewline "   -- NVSPBind `t`t" -ForegroundColor Yellow
                Copy-Item "$Apps\Utilities\NVSPBind" "\\$PC\$InstallFiles\NVSPBind" -Recurse
                CopyCheck "\\$PC\$InstallFiles\NVSPBind"

            # vESD
                Write-Host -NoNewline "   -- vESD `t`t" -ForegroundColor Yellow
                    
                $appToMatch = '*USAF vESD*'
                $Result = Get-InstalledSoftware -ComputerName $PC -Name $appToMatch

                if ($Result.name -ne $null)
                {
                    # It's installed already
                    Write-Host "Skipped, already installed" -ForegroundColor Green
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - vESD Copy Skipped, already installed" ; LogBoth $Text
                }
                else
                {
                    Copy-Item "$Apps\vESD\vESD_4.7.7678" "\\$PC\$InstallFiles\vESD"-Recurse
                    CopyCheck "\\$PC\$InstallFiles\vESD"
                }
            
            # ActivClient
                Write-Host -NoNewline "   -- ActivClient `t" -ForegroundColor Yellow
                $appToMatch = '*ActivClient*'
                $Result = Get-InstalledSoftware -ComputerName $PC -Name $appToMatch

                if ($Result.name -ne $null)
                {
                    # It's installed already
                    Write-Host "Skipped, already installed" -ForegroundColor Green
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - ActivClient Copy Skipped, already installed" ; LogBoth $Text
                }
                else
                {
                    Copy-Item "$Apps\ActivClient\SDC NIPR - ActivClient v7.2.x - 200409" "\\$PC\$InstallFiles\ActivClient" -Recurse
                    CopyCheck "\\$PC\$InstallFiles\ActivClient"
                }

            # USMT10
                Write-Host -NoNewline "   -- USMT `t`t" -ForegroundColor Yellow
                if (Test-Path "\\$PC\C$\USMT10")
                {
                    # Already there, move on!
                    Write-Host "Already exists" -ForegroundColor Green
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - USMT10 folder already exists" ; LogBoth $Text
                }
                else
                {
                    Copy-Item $USMTLocation "\\$PC\C$\USMT10" -Recurse -Force
                    CopyCheck "\\$PC\C$\USMT10"
                }
            
            # ConnectPST
                Write-Host -NoNewline "   -- ConnectPST `t" -ForegroundColor Yellow
                if (Test-Path "\\ZHTV-FS-601V\88CS\Groups\SDC\CST_Tools\ConnectPST\ConnectPST.ps1" -ErrorAction SilentlyContinue)
                {
                    Copy-Item "\\ZHTV-FS-601V\88CS\Groups\SDC\CST_Tools\ConnectPST\ConnectPST.ps1" "\\$PC\C$\Temp\ConnectPST.ps1"
                    CopyCheck "\\$PC\C$\Temp\ConnectPST.ps1"
                }
                else
                {
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Unable to access ConnectPST to copy it" ; LogBoth $Text
                }
            
            # GURS
                Write-Host -NoNewline "   -- GURS `t`t" -ForegroundColor Yellow
                Copy-Item "\\ZHTV-FS-601V\88CS\Groups\SDC\CST_Tools\GenerateUserRemapScript\GURS.ps1" "\\$PC\C$\Temp\GURS.ps1"
                CopyCheck "\\$PC\C$\Temp\GURS.ps1"

            # End of FileCopy

        # Start WLAN
            Write-Host -NoNewline " - WLAN Service `t" -ForegroundColor Yellow
            if ($Platform -EQ "Mobile")
                {
                    Set-Service -ComputerName $PC -Name "WLANSVC" -startuptype "automatic" | Out-Null
                    Set-Service -ComputerName $PC -Name "WLANSVC" -Status Running | Out-Null

                    $WLANService = Get-Service -ComputerName $PC -Name "WLANSVC" 
                    if ($WLANService.Status -NE "Running")
                    {
                        # Not running - Fail
                        Write-Host $WLANService.Status -ForegroundColor Red
                        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - WLAN Service is not running" ; LogBoth $Text
                        $ErrorTally++
                    }
                    else
                    {
                        # Service is running
                        Write-Host $WLANService.Status -ForegroundColor Green
                        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - WLAN Service running" ; LogBoth $Text
                    }
                }
                else
                {
                    Write-Host "Skipped (Desktop)" -ForegroundColor Green
                }

        # Set Power Options
            Write-Host -NoNewline " - Power Options `t" -ForegroundColor Yellow
            $CodeBlock = {C:\Windows\System32\powercfg.exe -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0}
            Invoke-Command -ComputerName $PC -ScriptBlock $CodeBlock
            $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Lid close action set to Do Nothing" ; LogBoth $Text
            Write-Host "Done" -ForegroundColor Green

        # Turn off Hibernation
            Write-Host -NoNewline " - Kill Hibernation `t" -ForegroundColor Yellow
            $CodeBlock = {C:\Windows\System32\powercfg.exe -h off}
            Invoke-Command -ComputerName $PC -ScriptBlock $CodeBlock
            $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Hibernation turned off" ; LogBoth $Text
            Write-Host "Done" -ForegroundColor Green

        # EURAM VPN
            Write-Host -NoNewline " - EURAM VPN `t`t" -ForegroundColor Yellow
            if (Test-Path "\\$PC\C$\Program Files (x86)\F5 VPN")
            {
                # Already installed
                Write-Host "Already Installed" -ForegroundColor Green
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - EURAM VPN already installed" ; LogBoth $Text
            }
            else
            {
                # Install it
                if ($Platform -EQ "Mobile")
                {
                    $CodeBlock = {Start-Process "C:\_Installs\LaptopLoad\AFNETVPN\EURAM_VPN\Install.cmd" -ArgumentList ">NUL" -Wait -NoNewWindow | Out-Null}
                    Invoke-Command -ComputerName $PC -ScriptBlock $CodeBlock

                    # Trust that it installed, but verify
                    if (Test-Path "\\$PC\C$\Program Files (x86)\F5 VPN")
                    {
                        # Installed successfully
                        Write-Host "Installed" -ForegroundColor Green
                        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - EURAM VPN installed successfully" ; LogBoth $Text
                    }
                    else
                    {
                        # Failed again.
                        Write-Host "Failed" -ForegroundColor Red
                        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - EURAM VPN failed to install" ; LogBoth $Text
                        $ErrorTally++
                    }
                }
                else
                {
                    Write-Host "Skipped (Desktop)" -ForegroundColor Green
                }
            }

        # JRSS VPN
            Write-Host -NoNewline " - JRSS VPN `t`t" -ForegroundColor Yellow
            if (Test-Path "\\$PC\C$\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe")
            {
                #Already installed - Skip this
                Write-Host "Already Installed"
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - JRSS VPN already installed" ; LogBoth $Text
            }
            else
            {
                #Install it
                if ($Platform -EQ "Mobile")
                {
                    $CodeBlock = {Start-Process "C:\_Installs\LaptopLoad\AFNETVPN\JRSS_VPN\Install.cmd" -argumentList ">NUL" -wait -NoNewWindow | Out-Null}
                    Invoke-Command -ComputerName $PC -ScriptBlock $CodeBlock

                    # Trust that it installed, but verify
                    if (Test-Path "\\$PC\C$\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe")
                    {
                        # Installed successfully
                        Write-Host "Installed" -ForegroundColor Green
                        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - JRSS VPN installed successfully" ; LogBoth $Text
                    }
                    else
                    {
                        # Failed again.
                        Write-Host "Failed" -ForegroundColor Red
                        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - JRSS VPN failed to install" ; LogBoth $Text
                        $ErrorTally++
                    }
                }
                else
                {
                    Write-Host "Skipped (Desktop)" -ForegroundColor Green
                }
            }

        # Add Groups to Local_Machine Administrators to enable Scans
            Write-Host " - Group Memberships `t" -ForegroundColor Yellow
            
            # WP Global Admins
                $DomainGroup = "WP Global Admins"
                Write-Host -NoNewline "   - $DomainGroup`t" -ForegroundColor Yellow
                # Check to ensure group is already present
                if (IsGroupAdmin $DomainGroup)
                {
                    # Group is already present, Skip
                    Write-Host "Already Present" -ForegroundColor Green
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - WP Global Admins already present in Local-Machine Administrators group" ; LogBoth $Text
                }
                else
                {
                    # Group is not there.  Add it
                    #([ADSI]"WinNT://$PC/$LocalGroup,group").psbase.Invoke("Add",([ADSI]"WinNT://$Domain/$DomainGroup").path) | Out-Null
                    Invoke-Command -ScriptBlock {net localgroup Administrators /add "$env:userdomain\WP Global Admins"} -Computer $PC | Out-Null

                    # Trust, but Verify
                    if (IsGroupAdmin $DomainGroup)
                    {
                        Write-Host "Success" -ForegroundColor Green
                        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - WP Global Admins added to Local-Machine Administrators group successfully" ; LogBoth $Text
                    }
                    else
                    {
                        Write-Host "Failed" -ForegroundColor Red
                        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - WP Global Admins failed to be added to Local-Machine Administrators group" ; LogBoth $Text
                        $ErrorTally++
                    }
                }

            # WP ESM Admins
                $DomainGroup = "WP ESM Admins"
                Write-Host -NoNewline "   - $DomainGroup`t" -ForegroundColor Yellow
                # Check to ensure group is already present
                if (IsGroupAdmin $DomainGroup)
                {
                    # Group is already present, Skip
                    Write-Host "Already Present" -ForegroundColor Green
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - WP ESM Admins already present in Local-Machine Administrators group" ; LogBoth $Text
                }
                else
                {
                    # Group is not there.  Add it
                    #([ADSI]"WinNT://$PC/$LocalGroup,group").psbase.Invoke("Add",([ADSI]"WinNT://$Domain/$DomainGroup").path) | Out-Null
                    Invoke-Command -ScriptBlock {net localgroup Administrators /add "$env:userdomain\WP ESM Admins"} -Computer $PC | Out-Null

                    # Trust, but Verify
                    if (IsGroupAdmin $DomainGroup)
                    {
                        Write-Host "Success" -ForegroundColor Green
                        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - WP ESM Admins added to Local-Machine Administrators group successfully" ; LogBoth $Text
                    }
                    else
                    {
                        Write-Host "Failed" -ForegroundColor Red
                        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - WP ESM Admins failed to be added to Local-Machine Administrators group" ; LogBoth $Text
                        $ErrorTally++
                    }
                }

            # WP IA Scans
                $DomainGroup = "WP IA Scans"
                Write-Host -NoNewline "   - $DomainGroup`t" -ForegroundColor Yellow
                # Check to ensure group is already present
                if (IsGroupAdmin $DomainGroup)
                {
                    # Group is already present, Skip
                    Write-Host "Already Present" -ForegroundColor Green
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - WP IA Scans already present in Local-Machine Administrators group" ; LogBoth $Text
                }
                else
                {
                    # Group is not there.  Add it
                    #([ADSI]"WinNT://$PC/$LocalGroup,group").psbase.Invoke("Add",([ADSI]"WinNT://$Domain/$DomainGroup").path) | Out-Null
                    Invoke-Command -ScriptBlock {net localgroup Administrators /add "$env:userdomain\WP IA Scans"} -Computer $PC| Out-Null

                    # Trust, but Verify
                    if (IsGroupAdmin $DomainGroup)
                    {
                        Write-Host "Success" -ForegroundColor Green
                        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - WP IA Scans added to Local-Machine Administrators group successfully" ; LogBoth $Text
                    }
                    else
                    {
                        Write-Host "Failed" -ForegroundColor Red
                        $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - WP IA Scans failed to be added to Local-Machine Administrators group" ; LogBoth $Text
                        $ErrorTally++
                    }
                }

        # Disable IPV6, QoS, and both Link-Layers for Local Area Connection
            Write-Host -NoNewline " - NIC Settings `t" -ForegroundColor Yellow
            
            $CodeBlock = {& C:\_Installs\NVSPBind\nvspbind.exe /d "Ethernet" ms_tcpip6 | out-null}
            Invoke-Command -ComputerName $PC -ScriptBlock $Codeblock -WarningAction SilentlyContinue
            
            $CodeBlock = {& C:\_Installs\NVSPBind\nvspbind.exe /d "Ethernet" ms_pacer | out-null}
            Invoke-Command -ComputerName $PC -ScriptBlock $Codeblock -WarningAction SilentlyContinue
            
            $CodeBlock = {& C:\_Installs\NVSPBind\nvspbind.exe /d "Ethernet" ms_lltdio | out-null}
            Invoke-Command -ComputerName $PC -ScriptBlock $Codeblock -WarningAction SilentlyContinue
            
            $CodeBlock = {& C:\_Installs\NVSPBind\nvspbind.exe /d "Ethernet" ms_rspndr | out-null}
            Invoke-Command -ComputerName $PC -ScriptBlock $Codeblock -WarningAction SilentlyContinue

            $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - NIC Settings complete" ; LogBoth $Text

            Write-Host "Done" -ForegroundColor Green

        # vESD
            Write-Host -NoNewline " - Virtual ESD `t`t" -ForegroundColor Yellow
            
            # Check to see if it's installed already
            $appToMatch = '*USAF vESD*'
            $Result = Get-InstalledSoftware -ComputerName $PC -Name $appToMatch

            if ($Result.name -ne $null)
            {
                # It's installed already
                $vESDVersion = $Result.Version
                Write-Host "Already installed (v.$vESDVersion)" -ForegroundColor Green
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - vESD version $vESDVersion already installed" ; LogBoth $Text
            }
            else
            {
                # Not installed, let's fix that
                $CodeBlock = {Start-Process "C:\_Installs\vESD\vESD.3.x.Installer_RELEASE_4.7.7678.msi" -argumentList "/quiet /norestart" -wait}
                Invoke-Command -ComputerName $PC -ScriptBlock $Codeblock

                # Trust, but Verify
                $appToMatch = '*USAF vESD*'
                $Result = Get-InstalledSoftware -ComputerName $PC -Name "*USAF vESD*"

                if ($Result.name -ne $null)
                {
                    # Install success
                    Write-Host "Installed" -ForegroundColor Green
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - vESD version $vESDVersion installed successfully" ; LogBoth $Text
                }
                else
                {
                    # Install Fail
                    Write-Host "Failed" -ForegroundColor Red
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - vESD failed to install" ; LogBoth $Text
                    $ErrorTally++
                }
            }

        # Install ActivClient
            Write-Host -NoNewline " - ActivClient `t`t" -ForegroundColor Yellow

            # Check to see if it's installed already
            $appToMatch = '*ActivClient*'
            $Result = Get-InstalledSoftware -ComputerName $PC -Name $appToMatch

            if ($Result.name -ne $null)
            {
                # It's installed already
                $ActivClientVersion = $Result.Version
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - ActivClient version $ActivClientVersion already installed" ; LogBoth $Text
                Write-Host "Already installed (v.$ActivClientVersion)" -ForegroundColor Green
            }
            else
            {
                # Not installed, let's fix that
                $CodeBlock = {Start-Process "C:\_Installs\ActivClient\Install.cmd" -Wait -WindowStyle Hidden}
                Invoke-Command -ComputerName $PC -ScriptBlock $Codeblock

                # Trust, but Verify
                $appToMatch = '*ActivClient*'
                $Result = Get-InstalledSoftware -ComputerName $PC -Name $appToMatch

                if ($Result.name -ne $null)
                {
                    # Install success
                    Write-Host "Installed" -ForegroundColor Green
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - ActivClient version $ActivClientVersion installed successfully" ; LogBoth $Text
                }
                else
                {
                    # Install Fail
                    Write-Host "Failed" -ForegroundColor Red
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - ActivClient failed to install" ; LogBoth $Text
                    $ErrorTally++
                }
            }

        # Perform an Orphan Check
            Write-Host -NoNewline " - Orphan Check `t" -ForegroundColor Yellow
            $Membership = ([adsisearcher]"(&(objectCategory=computer)(cn=$PC))").FindOne().Properties.memberof -replace '^CN=([^,]+).+$','$1' | where-object {$_ -like "*workstations"}

            if ($Membership.count -eq 1)
            {
                # Perfect
                Write-Host "Good" -ForegroundColor Green
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Orphan Check:  Not an orphan ($Membership)" ; LogBoth $Text
            }
            else
            {
                # Not good, is it zero or more than one?
                if ($Membership.count -eq 0)
                {
                    # Its an orphan
                    Write-Host "No _Workstations group - will be deleted at some point!" -ForegroundColor Red
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - ORPHAN COMPUTER!" ; LogBoth $Text
                    $ErrorTally++
                }

                if ($Membership.count -GT 1)
                {
                    # Its a member of more than one workstations group
                    Write-Host "More than one _Workstations group detected!" -ForegroundColor Red
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - More than one _Workstations group detected" ; LogBoth $Text
                    $ErrorTally++
                }
            }
        
        # Force Group Policy update
            Write-Host -NoNewline " - GPUpdate `t`t" -ForegroundColor Yellow
            if ($ADUCExist)
            {
                #ADUC exists, running remote GPUPDATE
                Invoke-GPUpdate -Computer $PC -Force -AsJob -RandomDelayInMinutes 0 -ErrorAction SilentlyContinue | Out-Null
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Forced group policy update initiated" ; LogBoth $Text
                Write-Host "Done" -ForegroundColor Green
            }
            else
            {
                # ADUC Not installed, let's see if we're working locally
                if ($PC -eq $ENV:ComputerName)
                {
                    # Yes we are, do it locally
                    GPUpdate /Force | out-null
                    Write-Host "Done" -ForegroundColor Green
                }
                else
                {
                    # Nope, fail
                    Write-Host "Skipped (No ADUC installed)" -ForegroundColor Yellow
                }
            }
            
        # Check for SecureBoot/UEFI BIOS
            Write-Host -NoNewline " - SecureBoot/UEFI `t" -ForegroundColor Yellow
            $SecureBoot = Invoke-Command -ComputerName $PC -ScriptBlock {Confirm-SecureBootUEFI}
            If ($SecureBoot)
            {
                #Good to go!
                Write-Host "Enabled" -ForegroundColor Green
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Secure Boot/UEFI BIOS is enabled" ; LogBoth $Text
            }
            else
            {
                #Failed
                Write-Host "Failed" -ForegroundColor Red
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Secure Boot/UEFI BIOS is not enabled" ; LogBoth $Text
                $ErrorTally++
            }

        # Check Device/Credential Guard Status
            Write-Host -NoNewline " - Dev/Cred Guard `t" -ForegroundColor Yellow
            $CredGuardError = 0
            $DevGuard = Get-CimInstance -ComputerName $PC –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard

            # See if Credential Guard is Enabled
            if ($DevGuard.SecurityServicesConfigured -contains 1) 
            {
                $CredGuardEnabled = "Enabled"
            }
            else
            {
                $CredGuardEnabled = "Disabled"
            }

            # See if Credential Guard is Running
            if ($DevGuard.SecurityServicesRunning -contains 1) 
            {
                $CredGuardError = 0
                $CredGuardRunning = "Running"
            }
            else
            {
                $CredGuardError = 1
                $CredGuardRunning = "Not Running"
            }

            if ($CredGuardError -eq 0)
            {
                Write-Host "$CredGuardEnabled, $CredGuardRunning" -ForegroundColor Green
            }
            else
            {
                Write-Host "$CredGuardEnabled, $CredGuardRunning" -ForegroundColor Red
                $ErrorTally++
            }
            $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Device/Credential Guard Status:  $CredGuardEnabled, $CredGuardRunning" ; LogBoth $Text

        # Check drivers to see if any problems are evident
            Write-Host -NoNewline " - Driver Check `t" -ForegroundColor Yellow
            $Devices = $Null
            $Devices = Get-CimInstance -ClassName Win32_PnPEntity -ComputerName $PC | Where-Object {$_.ConfigManagerErrorCode -ne 0 -AND $_.ConfigManagerErrorCode -ne 22 -AND $_.Caption -ne "Standard PS/2 Keyboard" -AND $_.Caption -ne "Microsoft PS/2 Mouse" -AND $_.Caption -ne "PS/2 Compatible Mouse"}
            $VideoAdapters = Get-CimInstance -ClassName win32_VideoController -ComputerName $PC | select Caption

            # Check for a Microsoft Basic Display Adapter
            foreach ($VideoAdapter in $VideoAdapters)
            {
                if ($videoAdapter.Caption -eq "Microsoft Basic Display Adapter")
                {
                    # Looks like we need to load a video adapter
                    $DriverTally++
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Detected Microsoft Basic Display Adapter" ; LogBoth $Text
                }
            }

            # Check to see if any devices are in an error state
            if ($Devices -ne $Null)
            {
                # Drivers in error state
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Detected Drivers in error state" ; LogBoth $Text
                $Text = "Drivers with Errors $Devices" ; LogBoth $Text
                $DriverTally++
            }
            else
            {
                # No Drivers in error state
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - No Drivers Detected in an error state" ; LogBoth $Text
            }

            # Final Reporting for the Driver Check (Combination of Display and other devices)
            if ($DriverTally -eq 0)
            {
                # All Devices look good!
                Write-Host "Done!" -ForegroundColor Green
            }
            else
            {
                Write-Host "Driver Issue(s) Detected" -ForegroundColor Red
                $ErrorTally++
            }
        
        # Clean up
            # Delete the install files
                Write-Host -NoNewline " - File cleanup `t" -ForegroundColor Yellow
                $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Removing install files" ; LogBoth $Text
                if (Test-Path \\$PC\$InstallFiles)
                {
                    Remove-Item \\$PC\$InstallFiles -Recurse -Force
                }
                Write-Host "Done" -ForegroundColor Green

            $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Grab & Go Script complete on $PC" ; LogBoth $Text
            $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Error Count:  $ErrorTally" ; LogBoth $Text
            #LogBoth $Separator

            # Release IP and Shutdown if requested, but only if the errortally is zero for this PC
                if ($FinalActionShutdown -and $ErrorTally -eq 0)
                {
                    # Shutdown requested
                    Write-Host -NoNewline " - System Shutdown`t" -ForegroundColor Yellow
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Releasing IP Address and shutting down" ; LogBoth $Text
                    
                    # Send shutdown command with 15 second timer
                    shutdown.exe /m \\$PC -s -f -t 15

                    # Release the IP while waiting to shut down
                    $Codeblock = {$process = Get-WmiObject Win32_NetworkAdapterConfiguration | Where { $_.IpEnabled -eq $true -and $_.DhcpEnabled -eq $true} ; $process.ReleaseDHCPLease()  | out-Null}
                    Invoke-Command -ComputerName $PC -ScriptBlock $CodeBlock -AsJob | Out-Null
                    Write-Host "Commands sent (15 second delay)" -ForegroundColor Green
                }
                else
                {
                    # Do Not Shutdown
                    $TimeStamp = Get-Date -Format "yyyyMMdd_HH:mm" ; $Text = "$TimeStamp - Shutdown not requested, or was prevented because PC had $ErrorTally errors" ; LogBoth $Text
                }

            

        # Assemble the results into an array for a final report
                $Results.ComputerName = $PC
                $Results.ErrorCount = $ErrorTally

                $Info = New-Object -TypeName PSObject -Property $Results
                $FinalReport += $Info

        $Counter++
    }

    # Produce a final Report
        Write-Host ""
        Write-Host $Separator -ForegroundColor White
        Write-Host -NoNewline "FINAL RESULTS - " -ForegroundColor White
        
        $sw.Stop()
        Write-Host -Object $([string]::Format('Overall Elapsed time (d:h:m:s): {0:d2}:{1:d2}:{2:d2}:{3:d2}',$sw.Elapsed.days,$sw.Elapsed.hours,$sw.Elapsed.minutes,$sw.Elapsed.seconds)) -ForegroundColor White
        
        Write-Host $Separator -ForegroundColor White
        LogLocal $Separator
        LogLocal "FINAL RESULTS"
        LogLocal $Separator

        $Counter = 1
        $Text = $FinalReport ; LogLocal $Text
        foreach ($Result in $FinalReport)
        {
            If ($Result.ErrorCount -eq 0)
            {
                # No Errors
                Write-Host "$Counter.`t" $Result.ComputerName "`tErrors: " $Result.ErrorCount -ForegroundColor Green
            }
            else
            {
                # Errors reported
                Write-Host "$Counter.`t" $Result.ComputerName "`tErrors: " $Result.ErrorCount -ForegroundColor Red
            }
            $Counter++
        }

        Write-Host $Separator -ForegroundColor White
        Write-Host "Check either of the logs for the system to review any details." -ForegroundColor White
        Write-Host "Log on the remote computer is found at: C:\Windows\Logs\GrabNGo.log" -ForegroundColor White
        Write-Host "Master log on this computer is found at: $RemoteG2Log" -ForegroundColor White
        Write-Host ""
Pause
Exit 


# SIG # Begin signature block
# MIIMSAYJKoZIhvcNAQcCoIIMOTCCDDUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUlQH1cpMkjcmQruB77VX1MF2E
# 7cigggmtMIIEoDCCA4igAwIBAgIBEjANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQG
# EwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAK
# BgNVBAsTA1BLSTEWMBQGA1UEAxMNRG9EIFJvb3QgQ0EgMzAeFw0xNTA5MjMxNTIz
# MDVaFw0yMTA5MjMxNTIzMDVaMF0xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMu
# IEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRgwFgYDVQQD
# Ew9ET0QgSUQgU1cgQ0EtMzcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCsrnKiqfWUYvBZ5poN5GMO6qotl7XJ4GGfg/lr8ipbPcgYScw8HLXrxakW0wA+
# uEk3Yka//bfUgtiLCqr2/SMYVISjXisglAHUiK1pnXl6ANJ3FGX4eio9XdbvifXj
# cMu462T3XoZAcbbwkk7j5G2P4uJn88h2GmprYJzePNLC38yMgi4FMRsPchVYpX3F
# xk2wXEOghyeSYvueXWOzEtEDCEyrumQxHfW3Oru0b6JrTZMpztOlaTd9ngKLrIcK
# aXEyGtrjlCokBmTALc6xnyKmUNf4R9Imo+lVbwSIycGnePOTrJccRTUbZsfXsFeD
# 0lIWGnHYrws1w9xarvIN7Gm9AgMBAAGjggFrMIIBZzAfBgNVHSMEGDAWgBRsipSi
# d7GAch2Behaq8tzOZu5FwDAdBgNVHQ4EFgQUFiR+9y3B75I/vkTnVF7p/he686Ew
# DgYDVR0PAQH/BAQDAgGGMEwGA1UdIARFMEMwCwYJYIZIAWUCAQskMAsGCWCGSAFl
# AgELJzALBglghkgBZQIBCyowDAYKYIZIAWUDAgEDDTAMBgpghkgBZQMCAQMRMBIG
# A1UdEwEB/wQIMAYBAf8CAQAwDAYDVR0kBAUwA4ABADA3BgNVHR8EMDAuMCygKqAo
# hiZodHRwOi8vY3JsLmRpc2EubWlsL2NybC9ET0RST09UQ0EzLmNybDBsBggrBgEF
# BQcBAQRgMF4wOgYIKwYBBQUHMAKGLmh0dHA6Ly9jcmwuZGlzYS5taWwvaXNzdWVk
# dG8vRE9EUk9PVENBM19JVC5wN2MwIAYIKwYBBQUHMAGGFGh0dHA6Ly9vY3NwLmRp
# c2EubWlsMA0GCSqGSIb3DQEBCwUAA4IBAQBZDRYy0oP+yD3OiDqM3liOggDDqJid
# DSkqmPMBpxTL9iyXCAqS5OUhzKQ2/N8gRYzO1o7JNIqez7kuwj1HJ0LH94jbjyMn
# vrWV34mhm1OzbG1y/88FvheQXLgld+tjojxYVhErbFGHnxMPw1X0VpbRTWrAcetl
# fMNKdwPUAH1GDfFmczuSfqwqZcapgJal9BWMIJoCXH1sUOHXmg/6anXx1d30OH9i
# TYV0to76oHTg6PEw7nwxNDgGcVgLDVyDAyTpfQCfhV4fSLI9cDTs4nA0SUgUga01
# d2h1Sp4r0PtksjJINJlYvLggvRWucI/MokLw5F6m+w6BN+t+kEggLn6TMIIFBTCC
# A+2gAwIBAgIDA7dzMA0GCSqGSIb3DQEBCwUAMF0xCzAJBgNVBAYTAlVTMRgwFgYD
# VQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJ
# MRgwFgYDVQQDEw9ET0QgSUQgU1cgQ0EtMzcwHhcNMTgwODAyMjAwNDA0WhcNMjEw
# OTIzMTUyMzA1WjB4MQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5t
# ZW50MQwwCgYDVQQLEwNEb0QxDDAKBgNVBAsTA1BLSTENMAsGA1UECxMEVVNBRjEk
# MCIGA1UEAxMbQ1MuODggQ1MgU0NPU0MuQ1lTUy0xOC0wMTlOMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhfRFCBXUhV7/0NO4+m50YW1jteV8LnXxEj/q
# +pOvx0il/SpvNvw3D+BTC4lJFgMRkOcLVujW3/Ve9v9ZoclrGA8ha79Ded6UTtgv
# gV0dUn7jn//o9RFEYM9ETuDn39vY0KL954v5XXBvWDDwfMx9OetChT59UHCihmJr
# avT5k/LxaQho3NqMtf03xhybR1hoDEubwMtCmNKuGUd7Q+mqnYSRzM0trkh0MoXV
# ahnNOp2GoBqfXFx0Nw0oAmp+2zOJi7RJdqAZ9l7/Mvd+U62RCwGSkGVq/OMcHVmF
# P37gEAYO3GHIO4FQFWgphwv0Bav90lHHEDvg7m3LKCKqI6QwowIDAQABo4IBsTCC
# Aa0wHwYDVR0jBBgwFoAUFiR+9y3B75I/vkTnVF7p/he686EwHQYDVR0OBBYEFKEq
# i2G7HpNtPUyORzs2BSzgQMHaMGcGCCsGAQUFBwEBBFswWTA1BggrBgEFBQcwAoYp
# aHR0cDovL2NybC5kaXNhLm1pbC9zaWduL0RPRElEU1dDQV8zNy5jZXIwIAYIKwYB
# BQUHMAGGFGh0dHA6Ly9vY3NwLmRpc2EubWlsMA4GA1UdDwEB/wQEAwIHgDATBgNV
# HSUEDDAKBggrBgEFBQcDAzCBiQYDVR0RBIGBMH+kfTB7MQswCQYDVQQGEwJVUzEY
# MBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAKBgNVBAsT
# A1BLSTENMAsGA1UECxMEVVNBRjEnMCUGA1UEAxMeUGF0dGVyc29uLk1pY2hhZWwu
# QS4xMDc2NTQ0NjUwMBYGA1UdIAQPMA0wCwYJYIZIAWUCAQsqMDkGA1UdHwQyMDAw
# LqAsoCqGKGh0dHA6Ly9jcmwuZGlzYS5taWwvY3JsL0RPRElEU1dDQV8zNy5jcmww
# DQYJKoZIhvcNAQELBQADggEBABz8o1pjOq9cLCXWl7aDBKkZ/E5vrjjEZFK2jGh1
# lOeuNoaZ6OypdCfv/tXyyTbTIm6yD9JhaGKW74A140fsZYx+WRZGvpObmd+ZSXUD
# qCBfSceGqSYWX3kAeDWWWXdKNyWPCoiz4pyFGdI0np2vvD5BGAgsmdAXHoAX4Gmh
# /VDaUpL1RwP0gibQRi19uWAAfDFGpuP+UzcDVJUD1F/uJOlNCuQ98a03G7zIGooW
# x940z7zYl0BLm04xLCdMBgAL6Sr7LV25L2sHt4vBHT0IJYzCks7Byh/KV0+TYkGi
# DG7bYq0t+n8Zi9Vt2/XDcfxB2iRdm1g+IP2o/9G2PGlwGMsxggIFMIICAQIBATBk
# MF0xCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNV
# BAsTA0RvRDEMMAoGA1UECxMDUEtJMRgwFgYDVQQDEw9ET0QgSUQgU1cgQ0EtMzcC
# AwO3czAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAjBgkqhkiG9w0BCQQxFgQUVUnqiI4X3Bfe5wXTSrNY1c+zoMwwDQYJKoZI
# hvcNAQEBBQAEggEAY6FEa6eXyyktrpt9Zyq4tCF2/kcrjV2Yx1Ajs9CLJ8/jNELP
# UuJ1zvYsEwQmJUF1tyty7WCEh+ChZo+wpUmhh/1PTZvbp3MkROvnffsUvZMN9J7o
# n36cZbg30AmzaL5ISww64p/iWdCtdSd+t/Ce8V8nYc56cG4a/auAhcoy6OF/cJBj
# S6CV3zecfyIQaOMb4Pjrq+zMpeBmzB9FVWwNt10mQ8RGX31a6WsL60Bw9HrYn/37
# 14LaOegvY80QAytZPzyyx+r8qY80lu6UAgw6JySkJRLQPImqjMg3zqb5h8gQDWhb
# rh+sBFHTChf1M6ofhvrmUtruznm0P47uXi0Tgg==
# SIG # End signature block
