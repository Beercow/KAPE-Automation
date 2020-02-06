If you try this out you need hyper-v enabled and rsat hyper-v tools installed. If it is a vm, you will need to run the following command to enable hyper-v:  
Enable-WindowsOptionalFeature –Online -FeatureName Microsoft-Hyper-V –All -NoRestart

Command to install rsat hyper-v:  
Install-WindowsFeature -Name RSAT-Hyper-V-Tools

To use the permanent subscription:  
In KAPE_Automation_Permanent.txt, Line 64: replace <PATH_TO_KAPE_EXE> with the location of kape (Example: C:\Kape\kape.exe)
DO NOT LEAVE A SPACE BEFORE THE | OR IT WILL NOT WORK  
Correct: ◙C:\Kape\kape.exe|  
Incorrect: ◙C:\KAPE\kape.exe |  
In KAPE_Automation_Permanent.txt, Line 66: change the drive letter in TargetInstance.Drive to where KAPE SFTP's the collection  
Run lines 1-72 in an elevated powershell prompt.

To remove:  
Run lines 74-81
