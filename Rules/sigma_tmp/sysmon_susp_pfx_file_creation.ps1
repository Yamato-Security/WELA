Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*.pfx") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
