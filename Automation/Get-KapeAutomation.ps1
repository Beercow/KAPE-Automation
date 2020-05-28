<#
    .SYNOPSIS
    Ths script will setup IIS and WebDAV to serve KAPE remotely, automate parsing with KAPE and send an email when complete
    .DESCRIPTION
    This script will automate collection and parsing with KAPE
    .EXAMPLE
    C:\PS> Get-KapeAutomation.ps1 
    
    .NOTES
    Author: Brian Maloney
    Date:   May 20, 2020    
#>

$currentDirectory = (Resolve-Path -Path ('.')).Path
Start-Transcript -Path "$currentDirectory\KAPE-Automation-Install.log"
Write-Host ""
Write-Host "KAPE configuration:" -ForegroundColor Yellow
Write-Host ""

$KAPEpath = Read-Host -Prompt 'Input path to KAPE, no trailing backslash'
$DriveLetter = Read-Host -Prompt 'Input drive letter to monitor, include colon'

Write-Host ""
Write-Host "Email parameters:" -ForegroundColor Yellow
Write-Host ""

$From = Read-Host -Prompt 'Who is the email from'
$To = Read-Host -Prompt 'Who is the email to'
$SMTPServer = Read-Host -Prompt 'SMTP server name'
$SMTPPort = Read-Host -Prompt 'SMTP port'
$userName = Read-Host -Prompt 'User name'

function Encrypt-Password {
    <#

        AUTHOR:         Keith Francis
        Description:    This script creates a scheduled task under the system account and runs a command to create a text file with an encrypted password.
                        Since this password is encrypted using the system account, only tasks run under the System account that use this text file for the
                        password will be able to decrypt this password. No other account can decrypt it. This way, the password is stored securely and not
                        in plain text in a powershell script. The encrypted password can be used to, for example, authenticate an email account that may be
                        used in a PS script that sends emails. I could not find another way to run a command under the system account in PowerShell so creating
                        a scheduled task and running it there under the system account will have to do

    #>

    #Task name. Call it whatever you want
    $taskName = "Create Secure Email Password"

    #This is the path and name where the encrypted password will be stored in a text file
    $filePath = "C:\Temp\"
    $fileName = "EncryptedPass.txt"

    #Create the filePath if it does not exist
    New-Item -ItemType Directory -Force -Path $filePath | Out-Null

    $fullPath = $filePath + $fileName

    #This is the password you are trying to encrypt. Doing -AsSecureString so that it doesn't show the password when you type it
    $userPassword = Read-Host -Prompt "User password" -AsSecureString

    #Convert the password back to plain text
    $userPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($userPassword))

    #Remove task with the name "Create Secure Email Password" if it already exists
    $task = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName}
    if (![string]::IsNullOrWhiteSpace($task))
    {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    #Create the action for the scheduled task. It will run powershell and execute the command specified below
    $action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
            -Argument "-command &{'$userPassword' | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File $fullPath}"

    #Register Scheduled task and then run it once to create the text file with the encrypted password
    Register-ScheduledTask -Action $action -TaskName $taskName -Description "Creates a text file with the encrypted email password" -User "System" -RunLevel Highest | Out-Null
    Start-ScheduledTask -TaskName $taskName

    #Remove the task after it is run
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false

    <#

    To get the password and use it somewhere like emailing, for example, use the Get-Content command to get the string from the text file 
    and convert it to SecureString. See the sample code below to see how to do this:

    **********************************************************************************

    $email = "someone@example.com"
    $pass = Get-Content "C:\SecureFolder\EncryptedPass.txt" | ConvertTo-SecureString
    $emailCredential = New-Object System.Net.NetworkCredential($email, $pass)

    **********************************************************************************

    #>
}

Encrypt-Password

$userPassword = Get-Content "C:\Temp\EncryptedPass.txt"
Remove-Item 'C:\Temp\EncryptedPass.txt'

Write-Host ""
Write-Host "Installing features. Please wait." -ForegroundColor Yellow
Write-Host ""

Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -NoRestart | Out-Null
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebDAV -NoRestart | Out-Null
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication -NoRestart | Out-Null
Enable-WindowsOptionalFeature -Online -FeatureName IIS-NetFxExtensibility45 -NoRestart | Out-Null

Write-Host "Installing features complete" -ForegroundColor Yellow
Write-Host ""
Write-Host "Setting up KAPE user and group" -ForegroundColor Yellow

$group = Read-Host -Prompt 'Group name for KAPE'
$user = Read-Host -Prompt 'User name for KAPE'
New-LocalGroup -Name $group
New-LocalUser -Name $user
Add-LocalGroupMember -Group $group -Member $user

Write-Host ""
Write-Host "KAPE user and group complete" -ForegroundColor Yellow
Write-Host ""
Write-Host "Setting up WebDAV for KAPE" -ForegroundColor Yellow
Write-Host ""

New-Website -Name "KAPE" -PhysicalPath "C:\inetpub\wwwroot"
New-WebVirtualDirectory -Site 'KAPE' -Name 'Kape' -PhysicalPath $KAPEpath
Set-WebConfigurationProperty -Filter 'system.webServer/security/authentication/windowsAuthentication' -Location 'KAPE' -Name enabled -Value True
Set-WebConfigurationProperty -Filter 'system.webServer/directoryBrowse' -Location 'KAPE' -Name enabled -Value True
Set-WebConfigurationProperty -Filter 'system.webServer/security/requestFiltering' -Location 'KAPE' -Name allowDoubleEscaping -Value True
Set-WebConfigurationProperty -Filter 'system.webserver/webdav/authoring' -Location 'KAPE' -Name enabled -Value True
Add-WebConfiguration -Filter '/system.webServer/webdav/authoringRules' -Location 'KAPE' -Value @{path="*";roles="KAPE Users";access="Read,Write,Source"}
$acl = Get-Acl $KAPEpath
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$group","ReadAndExecute","ContainerInherit,ObjectInherit","None","Allow")
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl $KAPEpath
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$group","Write","ContainerInherit,ObjectInherit","None","Deny")
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl $KAPEpath
Remove-Website -Name "Default Web Site"
Start-Sleep -s 1
Start-Website KAPE

Write-Host "WebDAV setup complete" -ForegroundColor Yellow
Write-Host ""
Write-Host "Configuring WMI Provider Host Quota Configuration" -ForegroundColor Yellow
Write-Host ""

$oWMI = get-wmiobject -Namespace root -Class __ProviderHostQuotaConfiguration
Write-Host "Current settings:"
Write-Host "MemoryPerHost:"$oWMI.MemoryPerHost
Write-Host "MemoryAllHosts:"$oWMI.MemoryAllHosts
Write-Host ""
$oWMI.MemoryPerHost=4294967296
$oWMI.MemoryAllHosts=8589934592
$oWMI.put() | Out-Null
Write-Host "New settings:"
Write-Host "MemoryPerHost:"$oWMI.MemoryPerHost
Write-Host "MemoryAllHosts:"$oWMI.MemoryAllHosts
Write-Host ""
Write-Host "WMI Provider Host Quota Configuration complete" -ForegroundColor Yellow
Write-Host ""
Write-Host "Setting up WMI subscription" -ForegroundColor Yellow
Write-Host ""

$text = {
param
(
    [Parameter(Mandatory)]
    [string]
    $TIName,

    [Parameter(Mandatory)]
    [string]
    $TIFileName,
    
    [Parameter(Mandatory)]
    [string]
    $Kape,
    
    [Parameter(Mandatory)]
    [string]
    $From,

    [Parameter(Mandatory)]
    [string]
    $To,
    
    [Parameter(Mandatory)]
    [string]
    $SMTPServer,

    [Parameter(Mandatory)]
    [string]
    $SMTPPort,
    
    [Parameter(Mandatory)]
    [string]
    $userName,

    [Parameter(Mandatory)]
    [string]
    $userPassword
    
)
function Send-ChangeNotification {
    $EmailBody = "
        KAPE results can be viewed at:`n`r
        $LinkPath

    "

    $Params = @{
        'From' = $From
        'Subject' = "Collection Complete for $asset"
        'To' = $To
        'SMTPServer' = $SMTPServer
        'Port' = $SMTPPort
        'Body' = $EmailBody
    }

    $userPassword = $userPassword | ConvertTo-SecureString
    $mycreds = New-Object System.Management.Automation.PSCredential ($userName, $userPassword)
    Send-MailMessage @Params -UseSsl -Credential $mycreds
}
Start-Transcript -Path "$($Env:SystemDrive)\Temp\KAPE-transcript.txt"
Write-Host "starting Script"
$TIName=$TIName -replace '"', ""
$fileEvent = $TIName
$filePath = $TIName.Substring(0, $TIName.lastIndexOf('\')) + "\"
$zipSearch = $TIFileName.split('_ConsoleLog_SFTP')[0]
$zipFile = Get-ChildItem $filePath | Where-Object {$_.Name -like "*"+$zipSearch+"*zip"}
$zipDir = $zipFile.BaseName
$zipName = $zipFile.Name
[void] (New-Item -Path $filePath$zipDir -ItemType Directory -Force)
$Shell = new-object -com Shell.Application
$Shell.Namespace("$filePath$zipDir").copyhere($Shell.NameSpace("$filePath$zipName").Items(),0x14)
$module = (Get-ChildItem $filePath$zipDir"\mout\--module").Name
$vdhxFile = $filePath+$zipDir+"\"+$zipDir+".vhdx"
Mount-DiskImage -ImagePath $vdhxFile -Passthru
$DriveLetter = (Get-DiskImage -ImagePath $vdhxFile | Get-Disk | Get-Partition | Get-Volume).DriveLetter+":\"
$mdest = $filePath+$zipDir+"\mout"
start-process -FilePath $Kape -ArgumentList "--msource $DriveLetter --mdest $mdest --mflush --module $module" -NoNewWindow -wait
Dismount-DiskImage -ImagePath $vdhxFile
Remove-Item $vdhxFile
$asset = $zipDir.split('_')[1]
$LinkPath = $filePath+$zipDir+"\mout"
Send-ChangeNotification
Stop-Transcript -WarningAction Ignore
}

$PScommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($text))

$fname = "KAPE Automation Filter"

$cname = "KAPE Automation Consumer"

$Kape = $KAPEpath+"\kape.exe"

Write-Host "Generating command line template" -ForegroundColor Yellow
Write-Host ""

$Command = [System.Text.Encoding]::Default.GetBytes("%TargetInstance.Name%◙%TargetInstance.FileName%◙"+$Kape+"◙"+$From+"◙"+$To+"◙"+$SMTPServer+"◙"+$SMTPPort+"◙"+$userName+"◙"+$UserPassword)
$Command = [System.Text.Encoding]::UTF8.GetString($Command)
$CommandLineTemplate = "cmd /c echo $Command| powershell -noprofile -encodedcommand $PScommand"

Write-Host "Command line template complete" -ForegroundColor Yellow
Write-Host ""
Write-Host "Generating query" -ForegroundColor Yellow
Write-Host ""

$query = "Select * from __InstanceCreationEvent within 30 where targetInstance isa 'Cim_Datafile' AND TargetInstance.Drive = '$DriveLetter' AND TargetInstance.Path LIKE '%KAPE_data_push_%' AND TargetInstance.FileName LIKE '%_ConsoleLog_SFTP%' AND TargetInstance.Extension = 'txt'"

Write-Host "Query complete" -ForegroundColor Yellow
Write-Host ""
Write-Host "Adding WMI event filter" -ForegroundColor Yellow
Write-Host ""

$WMIEventFilter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{Name=$fname;EventNameSpace="root\cimv2";QueryLanguage="WQL";Query=$query}

Write-Host "WMI event filter complete" -ForegroundColor Yellow
Write-Host ""
Write-Host "Adding WMI event consumer" -ForegroundColor Yellow
Write-Host ""

$WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name=$cname;CommandLineTemplate=$CommandLineTemplate}

Write-Host "WMI event consumer complete" -ForegroundColor Yellow
Write-Host ""
Write-Host "Creating bindings" -ForegroundColor Yellow
Write-Host ""

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$WMIEventFilter;Consumer=$WMIEventConsumer} | Out-Null

Write-Host "Bindings Complete" -ForegroundColor Yellow
Write-Host ""
Write-Host "Setup complete. System needs to reboot." -ForegroundColor Yellow
Write-Host ""
Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
Stop-Transcript -WarningAction Ignore

# Restart-Computer 
