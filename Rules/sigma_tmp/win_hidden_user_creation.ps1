Get-WinEvent -LogName Security | where {($_.ID -eq "4720" -and $_.message -match "TargetUserName.*.*$") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
