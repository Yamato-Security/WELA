Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Description.*Python Core") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
