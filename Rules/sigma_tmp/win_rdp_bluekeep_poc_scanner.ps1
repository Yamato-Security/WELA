Get-WinEvent -LogName Security | where {($_.ID -eq "4625" -and $_.message -match "AccountName.*AAAAAAA") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
