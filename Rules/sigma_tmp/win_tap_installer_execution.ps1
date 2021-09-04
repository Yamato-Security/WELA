Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\tapinstall.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
