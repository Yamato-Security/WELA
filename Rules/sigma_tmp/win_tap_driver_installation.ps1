Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and $_.message -match "ImagePath.*.*tap0901.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "6" -and $_.message -match "ImagePath.*.*tap0901.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Security | where {($_.ID -eq "4697" -and $_.message -match "ImagePath.*.*tap0901.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
