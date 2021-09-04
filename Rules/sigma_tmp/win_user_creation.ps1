Get-WinEvent -LogName Security | where {($_.ID -eq "4720") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
