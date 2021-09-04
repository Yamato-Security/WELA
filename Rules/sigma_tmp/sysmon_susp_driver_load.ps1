Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "6" -and $_.message -match "ImageLoaded.*.*\\Temp\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
