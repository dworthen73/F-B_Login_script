cls


$Path = $env:OneDrive
$Path


Robocopy "P:\" "$Path\Documents\Pdrive" /E /XO /R:0 /W:0 /log:C:\Temp\PDrive.txt /TEE
