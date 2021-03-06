cls
$ErrorActionPreference = 'silentlycontinue'

do{
  
   $i=3
while($True){
    $error.clear()
    $MappedDrives = Get-SmbMapping |where -property Status -Value Unavailable -EQ | select LocalPath,RemotePath
    foreach( $MappedDrive in $MappedDrives)
    {
        try {
            New-SmbMapping -LocalPath $MappedDrive.LocalPath -RemotePath $MappedDrive.RemotePath -Persistent $True
        } catch {
            Write-Host "There was an error mapping $MappedDrive.RemotePath to $MappedDrive.LocalPath"
        }
    }
    $i = $i - 1
    if($error.Count -eq 0 -Or $i -eq 0) {break}

    Start-Sleep -Seconds 20
}

start-job  -scriptblock {C:\logon\PS_PCinfo.ps1}
start-job  -scriptblock {C:\logon\PS_Programs_List.ps1}
start-sleep -Seconds 120

get-job | Stop-Job 

start-sleep -Seconds 28800

    }until($infinity)

    Exit