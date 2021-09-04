Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4103" -and $_.message -match "PS ATTACK!!!") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
