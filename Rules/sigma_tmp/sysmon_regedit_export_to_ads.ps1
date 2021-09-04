Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "15" -and $_.message -match "Image.*.*\\regedit.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
