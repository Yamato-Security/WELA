Get-WinEvent -LogName Microsoft-Windows-Windows Defender/Operational | where {($_.ID -eq "1013" -and $_.message -match "EventType.*4") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
