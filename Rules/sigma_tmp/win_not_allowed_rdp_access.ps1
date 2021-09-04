Get-WinEvent -LogName Security | where {($_.ID -eq "4825") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
