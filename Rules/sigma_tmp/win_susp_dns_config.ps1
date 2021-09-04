Get-WinEvent | where {($_.ID -eq "150" -or $_.ID -eq "770") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
