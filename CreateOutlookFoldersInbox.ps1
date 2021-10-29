##Leave the pst connected in Outlook and then run this ps##
$Global:localLogFile = "C:\Users\$($env:username)\AppData\Roaming\"

function main
{
    #Creating Outlook Object/Connection
    $outlook = New-Object -ComObject outlook.application
    $ns = $outlook.GetNameSpace("MAPI")
    #Setting Inbox Variable
    $olFolderInbox = 6
    #$inbox = $ns.GetDefaultFolder($olFolderInbox)
    $rootFolder = $ns.GetDefaultFolder($olFolderInbox).Parent
    $Global:localLogFile += "$($rootFolder.Name.Split('@')[0])_PSTs.log"
    #Returning all PST Files
    $pstFiles = $ns.Stores.Session.Stores | Where-Object -Property ExchangeStoreType -eq 3
    #Iterate through PST Files and get Folder Structures

    foreach ($pstFile in $pstFiles)
    {
        # Get pst file name to create a folder under users mail root directory
        $pstFileName = $pstFile.DisplayName

        $pstFileStore = $ns.GetFolderFromID($pstFile.StoreID)

        Write-Host "Creating $($pstFileName) in $($rootFolder.FullFolderPath) - " -NoNewline

        try
        {
            $rootFolder.Folders.Add($pstFileName) | Out-Null

            Write-Host "Successful" -ForegroundColor Green

            Write-Log "Creating $($pstFileName) in $($rootFolder.FullFolderPath) - Successful"
        }
        catch
        {
            Write-Host "Failed, ERROR: $($_)" -ForegroundColor Red

            Write-Log "Creating $($pstFileName) in $($rootFolder.FullFolderPath) - Failed"
        }

        Write-Host "Checking if there are any emails in the pst root folder of ($pstFileName)."

        Write-Log "Checking if there are any emails in the pst root folder of ($pstFileName)."

        if ($pstFileStore.Items.Count -gt 0)
        {
            Write-Host "Found emails in pst root folder, moving $($pstFileStore.Items.Count) emails to $($rootFolder.FullFolderPath)\$($pstFileName)."
            Write-Log "Found emails in pst root folder, moving $($pstFileStore.Items.Count) emails to $($rootFolder.FullFolderPath)\$($pstFileName)."

            $currEmailIndex = 1

            foreach ($email in $pstFileStore.Items)
            {
                Write-Host "Email ($($currEmailIndex)/$($pstFileStore.Items.Count)): $($email.Subject) - " -NoNewline

                try
                {
                    $email.Copy().Move($rootFolder.Folders($pstFileName)) | Out-Null

                    Write-Host "Successful" -ForegroundColor Green

                    Write-Log "Moving Email ($($currEmailIndex)/$($pstFileStore.Items.Count)) - Successful"
                }
                catch
                {
                    Write-Host "Failed, ERROR: $($_)"

                    Write-Log "Moving Email ($($currEmailIndex)/$($pstFileStore.Items.Count)) - Failed, ERROR: $($_)"
                }

                $currEmailIndex++
            }

            Write-Host "Finished moving emails from root folder of $($pstFileName)"

            Write-Log "Finished moving emails from root folder of $($pstFileName)"
        }
        else
        {
            Write-Host "No emails found in pst root folder of $($pstFileName)"

            Write-Log "No emails found in pst root folder of $($pstFileName)"
        }

        Write-Host "Checking if pst file ($($pstFileName)) has any folders."

        Write-Log "Checking if pst file ($($pstFileName)) has any folders."

        if ($pstFileStore.Folders.Count -gt 0)
        {
            Write-Host "Found $($pstFileStore.Folders.Count) folders in $($pstFileName)."

            Write-Log "Found $($pstFileStore.Folders.Count) folders in $($pstFileName)."

            $currFolderIndex = 1

            foreach ($pstFolder in $pstFileStore.Folders)
            {
            
                Write-Host "(Folder: $($currFolderIndex)/$($pstFileStore.Folders.Count)): Copying $($pstFolder.FullFolderPath) to $($rootFolder.FullFolderPath)\$($pstFileName)\$($pstFolder.Name) - " -NoNewline

                try
                {
                    $pstFolder.CopyTo($rootFolder.Folders($pstFileName)) | Out-Null

                    Write-Host "Successful" -ForegroundColor Green

                    Write-Log "(Folder: $($currFolderIndex)/$($pstFileStore.Folders.Count)): Copying $($pstFolder.FullFolderPath) to $($rootFolder.FullFolderPath)\$($pstFileName)\$($pstFolder.Name) - Successful"
                }
                catch
                {
                    Write-Host "Failed, ERROR: $($_)" -ForegroundColor Red

                    Write-Log "(Folder: $($currFolderIndex)/$($pstFileStore.Folders.Count)): Copying $($pstFolder.FullFolderPath) to $($rootFolder.FullFolderPath)\$($pstFileName)\$($pstFolder.Name) - Failed"
                }

                $currFolderIndex++
            }
        }
        else
        {
            Write-Host "PST file ($($pstFileName)) doesn't have any folders."

            Write-Log "PST file ($($pstFileName)) doen't have any folders."
        }

        <#
        $rootFolder = $rootFolder.Folders($pstFileName)

        GetFolders($rootFolder, $pstFileStore)
        
        $pstname = $file.DisplayName
        $foldername = $ns.Folders[$file.DisplayName].Folders

        foreach($folder in $foldername)
        {
            $folder
            GetSubfolders($folder)
        }
        #>
    }
}

function Write-Log
{
    param(
        [Parameter(Position=0,mandatory=$true)]
        [string] $text
    )

    Add-Content -Path $localLogFile -Value ("[" + (Get-Date -Format g) + "]" + $text)
}

function CreateFolder([System.__ComObject] $folderPath, [string] $newFolderName)
{
    try
    {
        $folderPath.Folders.Add($newFolderName)

        return $true
    }
    catch
    {
        Write-Host "Error Creating folder ($($newFolderName)) in $($folderPath.FullFolderPath)"
    }

    return $false
}

function GetFolders([System.__ComObject] $rootFolder, [System.__ComObject] $pstFolder)
{
    $pstFolders = $pstFolder.Folders | Foreach-Object {$_.Name}

    foreach ($pstFolder in $pstFolders)
    {
        # Check to see if the mail root already has a folder named after the pst
        if (!(DoesFolderExist $rootFolder, $pstFolder))
        {
            # The folder does not exist so lets create it
            if ((CreateFolder $rootFolder, $pstFolder))
            {
                # Folder was successfully created under mail root
                Write-Host "Created folder ($($pstFolder)) in $($rootFolder.FullFolderPath)"

                <# Check if this folder has any items under it
                if (DoesFolderHaveItems $pstFolder)
                {
                
                }
                else
                {
                
                }
                #>
            }
        }
        # Folder already exist under mail root
        else
        {
            # TODO: Check to see if the pst file contents
            Write-Host "Folder ($($folder)) already exists in $pstFolders"
        }

        GetFolders $folder
    }
}

function DoesFolderExist([System.__ComObject] $folderPath, [string] $newFolderName)
{
    #If exists don't create
    $exists = $folderPath.Folders | Where-Object { $_.name -eq $newFolderName }

    #if Doesn't exist create folder
    if(!$exists)
    {
        return $false
        <#
        foreach($mailfilefolder in $pstfolders)
        {
            $newFolderName = $rootfolder.Folders.Add($mailfilefolder.Name)
        }
        #>
    } 
    else
    {
        return $true
    }
}

function DoesFolderHaveItems([System.__ComObject] $folderPath)
{
    if ($folderPath.Items.Count -gt 0)
    {
        return $true
    }
    else
    {
        return $false
    }
}

function GetSubfolders($Parent) 
{  
    $folders = $Parent.Folders  
    foreach ($folder in $folders) 
    {  
        $Subfolder = $Parent.Folders.Item($folder.Name)  
        Write-Host($folder.Name)  
        GetSubfolders($Subfolder)  
    }  
}

main