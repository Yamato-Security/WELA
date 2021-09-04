Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "3" -and $_.message -match "Image.*.*\\regsvr32.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "22" -and $_.message -match "Image.*.*\\regsvr32.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
