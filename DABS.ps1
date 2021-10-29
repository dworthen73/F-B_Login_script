<#
    DAta Backup Script (DABS)
    Author:  PATTERSON, MICHAEL A GS-12 USAF AFMC 88 CS/SCOSC
    Initial version: April 2020
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Script is designed to be run by a user without administrative assistance.  It will:
    - Pre-identify what folders to look for files to backup
      -- Desktop     Contacts     Documents
      -- Downloads   Favorites    Links
      -- Music       Pictures     Videos
      -- C:\Temp     C:\Data      Signatures
    - Shutdown Outlook if it's running (It can interfere with PST's)
    - Create folder to store log file: C:\Users\<Profile>\BackupLogs
    - Create folder to store uncyncable files:  C:\Users\<Profile>\UnsyncableFiles
    - Check for OneDrive Folder in profile: C:\Users\<Profile>\OneDrive - United States Air Force
    - Check for OneDrive process to be running (this is the process that syncs files)
    - Creates a User-Remap script on the desktop that will help the user remap Shares/Printers/PST's
    - Looks in pre-identified folders to find unsyncable files (*.PST *.MP3 *.EXE *.MOV *.WMV *.MP4)
      -- Consolidates (copies) them to UnsyncableFile Location
    - Scans files in pre-identified locations, tallys up size and gives report
    - Copies remaining files to OneDrive\Work-Backup
#>

function Copy-Files{
		param(
            [string] $Source
        )

        $FolderName = $Source | Split-Path -leaf

        #Use RoboCopy to move $Source to $Destination, skipping over PST MP3 EXE MOV WMV MP4
        Write-Host "Copying $FolderName to OneDrive..."
        Robocopy "$Source" "$Destination\$FolderName" /E /XF *.PST *.MP3 *.EXE *.MOV *.WMV *.MP4 /R:0 /w:0 /TEE /log+:$LogFileLocation\Backup-log.txt /XJD
}

function Move-Unsyncables{
		param(
            [string] $Source
        )
        
        $ParentFolderName = $Source | Split-Path -leaf
        $LocationToPutFiles = $UnsyncableFilesLocation + "\$ParentFolderName"
        Get-ChildItem $Source -Recurse -Include "*.pst","*.mp3","*.mov","*.wmv","*.mp4","*.exe" | Foreach-Object `
            {
                $destDir = Split-Path ($_.FullName -Replace [regex]::Escape($Source), $LocationToPutFiles)
                #$destDir = $destDir + "\$ParentFolderName"
                if (!(Test-Path $destDir))
                {
                    New-Item -ItemType directory $destDir | Out-Null
                }
                Copy-Item $_ -Destination $destDir -Force
            }
}
    [console]::ForegroundColor = "White"
    [console]::BackgroundColor = "Black"
    Clear-Host

# Variable setup
    #DAPS Variables
    $Version ="1.0"
    $Separator = '~' * 46
    $OneDriveLocation = "$env:USERPROFILE\OneDrive - United States Air Force"
    $Destination = "$env:USERPROFILE\OneDrive - United States Air Force\Work-Backup"
    $LogFileLocation = "$env:USERPROFILE\BackupLogs"
    $LogFile = "$LogFileLocation\Backup-Log.txt"
    $TotalSize = 0
    $TotalCount = 0
    $UnsyncableFilesLocation = "$env:USERPROFILE\UnsyncableFiles"
    # Define which folders to back up
    $FoldersToBackup = @()
        $FoldersToBackup += "$env:USERPROFILE\Desktop"
        $FoldersToBackup += "$env:USERPROFILE\Contacts"
        $FoldersToBackup += "$env:USERPROFILE\Documents"
        $FoldersToBackup += "$env:USERPROFILE\Downloads"
        $FoldersToBackup += "$env:USERPROFILE\Favorites"
        $FoldersToBackup += "$env:USERPROFILE\Links"
        $FoldersToBackup += "$env:USERPROFILE\Music"
        $FoldersToBackup += "$env:USERPROFILE\Pictures"
        $FoldersToBackup += "$env:USERPROFILE\Videos"
        $FoldersToBackup += "$env:USERPROFILE\AppData\Roaming\Microsoft\Signatures"
        #$FoldersToBackup += "C:\Temp"
        $FoldersToBackup += "C:\Data"
    #GURS Variables
    $GURSFileName = "UserRemap.ps1"
    $GURSPath = [environment]::getfolderpath("Desktop") # Get path to desktop
    $Domain = $env:userdomain
    $EDIPI = $env:username
    $ComputerName = $env:ComputerName
    $UserName = ([adsi]"WinNT://$Domain/$EDIPI,user").fullname
    $OutputFile = "$GURSPath\$GURSFileName"
    $PrinterCount = 0
    $ShareCount = 0
    $PSTCount = 0
$Banner = @"
________      _____ __________  _________
\______ \    /  _  \\______   \/   _____/
 |    |  \  /  /_\  \|    |  _/\_____  \ 
 |    `    \/    |    \    |   \/        \
/_______  /\____|__  /______  /_______  /
        \/         \/       \/        \/
          DAta Backup Script V$Version
"@

Write-Host $Banner -ForegroundColor Magenta
Write-Host "$Separator`n" -ForegroundColor White

#Pre-Flight Checks
    Write-Host "Pre-Flight Checks:"
    
    # Kill processes that may interfere
        Write-Host "Closing Apps that can interfere" -ForegroundColor Yellow
        if (Get-Process Outlook -ErrorAction SilentlyContinue)
        {
            Write-Host -NoNewline "- Closing Outlook          : " -ForegroundColor Yellow
            Get-Process Outlook -ErrorAction SilentlyContinue | Stop-Process -force
            Write-Host "Done!" -ForegroundColor Green
        }

    # Check for Log File Location, if not found, create it
        Write-Host -NoNewline "- Log File Location        : " -ForegroundColor Yellow
        if (!(Test-Path $LogFileLocation -ErrorAction SilentlyContinue))
            {
                New-Item -ItemType Directory -Force -path $LogFileLocation | Out-Null
                Write-Host "Created!" -ForegroundColor Green
            }
            else
            {
                Write-Host "Found!" -ForegroundColor Green
            }

    # Check for Unsyncable Files Location, if not found, create it
        Write-Host -NoNewline "- Unsyncable Files Location: " -ForegroundColor Yellow
        if (!(Test-Path $UnsyncableFilesLocation -ErrorAction SilentlyContinue))
            {
                New-Item -ItemType Directory -Force -path $UnsyncableFilesLocation | Out-Null
                Write-Host "Created!" -ForegroundColor Green
            }
            else
            {
                Write-Host "Found!" -ForegroundColor Green
            }

    # Check for OneDrive
        # Check for folder existence
        Write-Host -NoNewline "- OneDrive Folder          : " -ForegroundColor Yellow
        if (!(test-path $OneDriveLocation -ErrorAction SilentlyContinue))
            {
                # Not found
                Write-Host "Not Found!" -ForegroundColor Red
                Write-Host "One Drive folder does not exist.  Please set up One Drive using instructions" -ForegroundColor Red
                Write-Host "Script aborting..." -ForegroundColor Red
                exit
            }
            else
            {
                # Found it!
                Write-Host "Found!" -ForegroundColor Green
            }

    # Check for actively running OneDrive Sync application
        Write-Host -NoNewline "- OneDrive Sync App        : " -ForegroundColor Yellow
        if (!(Get-Process OneDrive -ErrorAction SilentlyContinue))
            {
                # Not found
                Write-host -NoNewline "Starting..." -ForegroundColor Yellow
                Start-Process -FilePath "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe" -ArgumentList "/background"
                Start-Sleep 5
                if (!(Get-Process OneDrive -ErrorAction SilentlyContinue))
                    {
                        # Still not running.  Abort
                        Write-Host "Not Running" -ForegroundColor Red
                        Write-Host "Script aborting..." -ForegroundColor Red
                        exit
                    }
                    else
                    {
                        Write-Host "Running!" -ForegroundColor Green
                    }
            }
            else
            {
                # Found
                Write-Host "Running!" -ForegroundColor Green
            }

    # Delete UserRemap.PS1 if found on desktop
        Write-Host -NoNewline "- Checking for UserRemap   : " -ForegroundColor Yellow
        if(Test-Path $OutputFile)
        {
            Remove-Item $OutputFile -Force
            Write-Host "Removed!" -ForegroundColor Green
        }
        else
        {
            # Not found
            Write-Host "Clear!" -ForegroundColor Green
        }

    # End of PreFlight Checks
        Write-Host "Preflight Checks complete!" -ForegroundColor Green
        Write-Host "$Separator" -ForegroundColor White

    # Run the GURS routine
        # Generate a line in file that states where it came from
        $Timestamp = Get-Date
        $Text = "# Script generated by $UserName using GURS (via DABS) `n# Version $Version on $Timestamp `n# Computer Name: $ComputerName`n# $Separator`n"
        $Text | Add-Content $OutputFile

        $Text = "Clear-Host"
        $Text | Add-Content $OutputFile

    # Identify network printers then generate PS1 code to re-map printers
        $Text = 'Write-Host "Mapping Printers... Please wait..."'
        $Text | Add-Content $OutputFile
        
        Write-Host "- Reading printers" -ForegroundColor White
        $printers=gwmi -class win32_printer -Filter network="True"| select name
        foreach($printer in $printers)
        {
            $print=$printer.name
            Write-Host "  -- $print" -ForegroundColor Yellow
            $pline="(New-Object -ComObject WScript.Network).addwindowsPrinterConnection("+"""$print""" +")"
            $pline | add-content $OutputFile
            $PrinterCount++
        }

    # Identify network shares and generate PS1 code to re-map share drives
        $Text = 'Write-Host "Mapping Drives...   Please wait..."'
        $Text | Add-Content $OutputFile

        Write-Host "- Reading Shared Drives" -ForegroundColor White
        $mappeddrives=gwmi -class "Win32_MappedLogicalDisk" | select providername, name
        $mapeddriver
        foreach ($mappeddrive in $mappeddrives)
        {
            $providername=$mappeddrive.providername
            $fName=$mappeddrive.name
            $gName=$fName.Substring(0,1)
            Write-Host "  -- $fname $providername" -ForegroundColor Yellow
            $mline='Net Use ' + $fname + ' "' + $providername + '" /p:y | Out-Null'
            $mline | add-content $OutputFile
            $ShareCount++
        }

    # Locate PST files and generate PS1 code to re-map PST file(s)
        $Text = 'Write-Host "Connecting PSTs...  Please wait..."'
        $Text | Add-Content $OutputFile

        Write-Host "- Looking for PST files" -ForegroundColor White
        $outlook = New-Object -comObject Outlook.Application 
        $outPSts=$outlook.Session.Stores | where { ($_.FilePath -like '*.PST') }

        "Add-type -assembly " + "Microsoft.Office.Interop.Outlook" + " | out-null" | add-content $OutputFile
        '$outlook' + " = new-object -comobject outlook.application" | add-content $OutputFile
        '$namespace' + " = " +'$outlook.GetNameSpace' + "(" + """MAPI""" + ")" | add-content $OutputFile
        $outlook = New-Object -comObject Outlook.Application 
        $outPSts=$outlook.Session.Stores | where { ($_.FilePath -like '*.PST') }
        $count=[environment]::GetFolderPath("desktop").Length
        $count=$count-8
        foreach ($outPst in $outPSts)
        {
            if($outPst.FilePath -like "c:\users*")
            {
                $Cloc='C:\users\'+ [environment]::username + $outpst.FilePath.Substring($count)
            }
            else
            {
                $cloc=$outPst.FilePath
            }
            "dir """ + $cloc + """ | % { " + '$namespace.AddStore($_.FullName)' + " }"| add-content $OutputFile
            Write-Host "  -- $cloc" -ForegroundColor Yellow
            $PSTCount++
        }

        $Text = 'Pause'
        $Text | Add-Content $OutputFile

        # Display a summary
        Write-Host "Printers found: $PrinterCount" -ForegroundColor Green
        Write-Host "Shares found: $ShareCount" -ForegroundColor Green
        Write-Host "PST's found: $PSTCount" -ForegroundColor Green
        Write-Host "Re-mapping script placed at $OutputFile" -ForegroundColor Green
        Write-Host "You can use this script on any computer to remap these printers/shares." -ForegroundColor Green

        Write-Host $Separator

    # End of GURS Routine

    # Sort out the unsyncables and collect them in a folder
        Write-Host "Searching for files that are prohibited on OneDrive...  (MP3 EXE MOV WMV MP4)"
        Foreach ($Folder in $FoldersToBackup)
        {
            if (Test-Path $Folder)
            {
                Write-Host "- Scanning: $Folder" -ForegroundColor Yellow
                Move-Unsyncables $Folder
            }
        }

        $ProhibitedFileCount = (Get-ChildItem $UnsyncableFilesLocation -recurse).count
        Write-Host "Scanning complete, $ProhibitedFileCount prohibited files found and consolidated (copied) to:" -ForegroundColor Green
        Write-Host $UnsyncableFilesLocation -ForegroundColor Green
        
        Write-Host "$Separator" -ForegroundColor White

    # Let's take a look at the size of the files to copy
        Write-Host "Calculating size of data to copy"
        Foreach ($Folder in $FoldersToBackup)
        {
            if (Test-Path $Folder)
            {
                Write-Host -NoNewline "- Examining $Folder... " -ForegroundColor Yellow
                $Size = 0
                $Count = 0

                $Size = "{0:N2}" -f ((Get-ChildItem $Folder -recurse | Measure-Object -property length -sum).sum / 1MB) 
                $Count = (Get-ChildItem $Folder -recurse | Measure-Object).count
            
                Write-Host "$Count Items, $Size(MB)"

                $TotalSize = $TotalSize + $Size
                $TotalCount = $TotalCount + $Count
            }
        }

        Write-Host "Total Profile size to copy:  $TotalCount Files, totalling $TotalSize(MB)" -ForegroundColor Green

    Write-Host "$Separator" -ForegroundColor White

    Write-Host  -NoNewline "Filecopy is about to begin...  " -ForegroundColor Cyan
    
    Pause

    Write-Host "$Separator" -ForegroundColor White

    # Copy the remaining files to OneDrive
        Write-Host "Copying files to OneDrive"
        Foreach ($Folder in $FoldersToBackup)
        {
            # Reset the Item Count
            #$ItemCount = 0

            if (Test-Path $Folder)
            {
                # Folder exists, test to see if the folder is empty.  If not, copy it.  Otherwise skip it.
                $ItemCount = (Get-ChildItem -Path $folder -Recurse -Exclude "*.pst","*.mp3","*.mov","*.wmv","*.mp4","*.exe").count
                if ($ItemCount -EQ 0)
                {
                    #Folder is empty
                    Write-Host "- Skipping: $Folder (Empty Folder)" -ForegroundColor Yellow
                }
                else
                {
                    
                    #Folder is not empty
                    Write-Host "- Copying : $Folder" -ForegroundColor Yellow
                    Copy-Files $Folder
                }
            }
        }

        Write-Host "Copy Complete." -ForegroundColor Green

# All Done, finish up and give further notices/instructions

    Write-Host "$Separator" -ForegroundColor White
    Write-Host "Pausing 10 seconds"
    Write-Host "$Separator" -ForegroundColor White

    Start-Sleep 10

    Clear-Host

    Write-Host $Banner -ForegroundColor Magenta
    Write-Host "$Separator`n" -ForegroundColor White

    #Final Report
        Write-Host "Script complete" -ForegroundColor Green
        Write-Host $Separator -ForegroundColor White
        Write-Host "Total copied:  $TotalCount Files, totalling $TotalSize(MB)" -ForegroundColor Green
        Write-Host "A full log of the file copy can be found at $LogFile" -ForegroundColor Green
        Write-Host "Please note:  It is in your best interest to verify the files you need were indeed backed up." -ForegroundColor Green
        Write-Host "You should find this copy here: $Destination" -ForegroundColor Green
        Write-Host "You can copy additional files here if you desire."  -ForegroundColor Green
        Write-Host "If you have questions/problems, Your Cyberspace Liaison may be best able to assist." -ForegroundColor Green
        Write-Host $Separator
        Write-Host "It may take time for your OneDrive to fully sync to the cloud." -ForegroundColor Cyan
        Write-Host "Please be sure it is done before logging off." -ForegroundColor Cyan
        Write-Host "While syncing, the OneDrive icon on the task bar (looks like a blue cloud) will have a"  -ForegroundColor Cyan
        Write-Host "small circle with two arrows on it." -ForegroundColor Cyan
        Write-Host "WHen done syncing, those circled arrows will go away, leaving just the blue cloud icon." -ForegroundColor Cyan
        Write-Host "Note, you may need to click the upward-pointing arrow to see all of the icons in the taskbar system tray" -ForegroundColor Cyan
        Write-Host $Separator
        
    # If any Unsyncables found, give instructions for those

        if ($ProhibitedFileCount -NE 0)
        {
            Write-Host "$ProhibitedFileCount files found that are prohibited on OneDrive and were consolidated (copied)" -ForegroundColor Yellow
            Write-Host -NoNewline  "to $UnsyncableFilesLocation for your convenience.  " -ForegroundColor Yellow
            Write-Host "These $ProhibitedFileCount files are not backed up yet!" -ForegroundColor Red
            Write-Host "Please seek other means of transferring these files.  Your Cyberspace Liaison may be best able to assist." -ForegroundColor Yellow
        }
        Write-Host $Separator -ForegroundColor White      
Pause
# SIG # Begin signature block
# MIIMSAYJKoZIhvcNAQcCoIIMOTCCDDUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU8dVYPwy+BOK2LL1OSdCBZCHm
# nQKgggmtMIIEoDCCA4igAwIBAgIBEjANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQG
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
# NwIBFTAjBgkqhkiG9w0BCQQxFgQU7/y+xh30Hgq7G/mByvY08Dlckz0wDQYJKoZI
# hvcNAQEBBQAEggEAQILs2bg9/ZBEg+89JDaXZNujlWZ2O1MWx4vp6Df1jJMkQEx/
# 2tc5yXrn/dFjeK8FAuKJqhrbEDkAK33GAYbYTlGOVL5UwreLbOI3uV7s80m/3gl4
# P0yven3khpjozfAGJIqWKYat8O9I2AFrFNpFfDkK30v8pAREj1kmBDaNN+7krbCe
# H10XEMlrghNHAFgaf8hbEkI2bh1ZWos+QYic5cbzZUoSVUb2Qi2oH6vhm4iQ+MRR
# crpBxCzMEM3g2I/i1TuCNwb7RTXPNqJh7YVhwvD6yRZNHWHhCAR8aYKXsEESwJTG
# DaFSWx7tsLCGm0xM//X0tFk5/dPlzeZbsEVwFw==
# SIG # End signature block
