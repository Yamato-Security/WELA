Get-WinEvent -LogName Security | where {(($_.ID -eq "4720" -or $_.ID -eq "4781") -and $_.message -match "SamAccountName.*.*$.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
