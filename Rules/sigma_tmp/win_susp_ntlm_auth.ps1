Get-WinEvent -LogName Microsoft-Windows-NTLM/Operational | where {($_.ID -eq "8002" -and $_.message -match "CallingProcessName.*.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
