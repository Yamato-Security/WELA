Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and $_.message -match "ServiceName.*WerFaultSvc") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
