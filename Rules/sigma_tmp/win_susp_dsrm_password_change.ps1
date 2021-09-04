Get-WinEvent -LogName Security | where {($_.ID -eq "4794") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
