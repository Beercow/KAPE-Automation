$action = {
    Write-Host "Filter Fired"
    $fileEvent = $Event.SourceEventArgs.NewEvent.TargetInstance.Name
    $fileEvent
    $filePath = $Event.SourceEventArgs.NewEvent.TargetInstance.Drive + $Event.SourceEventArgs.NewEvent.TargetInstance.Path
    $zipSearch = $Event.SourceEventArgs.NewEvent.TargetInstance.FileName.split('_ConsoleLog_SFTP')[0]
    $zipFile = Get-ChildItem $filePath | Where-Object {$_.Name -like "*"+$zipSearch+"*zip"}
    $zipDir = $zipFile.BaseName
    $zipName = $zipFile.Name
    [void] (New-Item -Path $filePath$zipDir -ItemType Directory -Force)
    $Shell = new-object -com Shell.Application
    $Shell.Namespace("$filePath$zipDir").copyhere($Shell.NameSpace("$filePath$zipName").Items(),0x14)
    $vdhxFile = $filePath+$zipDir+"\"+$zipDir+".vhdx"
    Mount-VHD -Path $vdhxFile -Passthru
    Dismount-VHD -Path $vdhxFile
    $DriveLetter = (Mount-VHD -Path $vdhxFile -ReadOnly -Passthru | Get-Disk | Get-Partition | Get-Volume).DriveLetter
    F:\KAPE\kape.exe --msource $DriveLetter":\" --mdest $filePath$zipDir"\mout" --mflush --module !ALL --debug --trace
    Dismount-VHD -Path $vdhxFile
    Remove-Item $vdhxFile 
}

$query = @"
 Select * from __InstanceCreationEvent within 10
 where targetInstance isa 'Cim_Datafile'
 AND TargetInstance.Drive = 'F:'
 AND TargetInstance.Path LIKE '%KAPE_data_push_%'
 AND TargetInstance.FileName LIKE '%_ConsoleLog_SFTP%'
 AND TargetInstance.Extension = 'txt'
"@

Register-WmiEvent -Query $query -SourceIdentifier "KAPE_Automation" -Action $action

<# Function Remove-WMIEventAndSubscriber
{
 Get-EventSubscriber | Unregister-Event
 Get-Event | Remove-Event
} #end function Remove-WmiEventAndSubscriber #>