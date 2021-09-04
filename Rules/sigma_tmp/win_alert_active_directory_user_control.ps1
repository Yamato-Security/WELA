Get-WinEvent -LogName Security | where {($_.ID -eq "4704" -and ($_.message -match ".*SeEnableDelegationPrivilege.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
