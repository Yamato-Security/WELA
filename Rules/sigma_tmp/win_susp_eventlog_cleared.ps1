Get-WinEvent -LogName Security | where {(($_.ID -eq "517" -or $_.ID -eq "1102")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName System | where {($_.ID -eq "104" -and $_.message -match "Source.*Microsoft-Windows-Eventlog") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
