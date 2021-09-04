Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "3" -and $_.message -match "Image.*.*wuauclt.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
