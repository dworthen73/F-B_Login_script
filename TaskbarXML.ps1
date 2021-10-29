function New-XmlSchema
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $_ })]
        [ValidatePattern('\.xml')]
        [string]$XmlExample
    ) 

    $item = Get-Item $XmlExample
    $dir = $item.Directory
    $name = $item.Name
    $baseName = $item.BaseName

    ## build the schema path by replacing '.xml' with '.xsd'
    $SchemaPath = "$dir\$baseName.xsd"

    try
    {
        $dataSet = New-Object -TypeName System.Data.DataSet
        $dataSet.ReadXml($XmlExample) | Out-Null
        $dataSet.WriteXmlSchema($SchemaPath)
        
        ## show the resulted schema file
        Get-Item $SchemaPath
    }
    catch
    {
        $err = $_.Exception.Message
        Write-Host "Failed to create XML schema for $XmlExample`nDetails: $err" -ForegroundColor Red
    }
}

#<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
    Version="1">
  <CustomTaskbarLayoutCollection>
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
        <taskbar:DesktopApp DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Accessories\Paint.lnk" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Microsoft Endpoint Manager\Configuration Manager" />
        <taskbar:UWA AppUserModelID="Microsoft.Reader_8wekyb3d8bbwe!Microsoft.Reader" />
        <taskbar:UWA AppUserModelID="Microsoft.Skydrive.Desktop" />
        <taskbar:UWA AppUserModelID="MSEdge" />
        <taskbar:UWA AppUserModelID="Chrome" />
        <taskbar:DesktopApp DesktopApplicationLinkPath="%appdata%\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk" />
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>

#C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Endpoint Manager\Configuration Manager