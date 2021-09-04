Get-WinEvent -LogName Application | where {($_.ID -eq "524" -and $_.message -match "Source.*Microsoft-Windows-Backup") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
