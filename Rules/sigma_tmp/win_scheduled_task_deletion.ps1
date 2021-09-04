Get-WinEvent -LogName Security | where {($_.ID -eq "4699") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
