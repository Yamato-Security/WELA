Get-WinEvent -LogName Security | where {($_.ID -eq "4692") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
