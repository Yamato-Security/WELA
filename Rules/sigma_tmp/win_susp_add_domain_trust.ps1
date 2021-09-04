Get-WinEvent -LogName Security | where {($_.ID -eq "4706") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
