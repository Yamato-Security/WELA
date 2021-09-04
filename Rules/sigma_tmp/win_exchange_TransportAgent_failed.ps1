Get-WinEvent -LogName MSExchange Management | where {($_.message -match ".*Install-TransportAgent.*" -and $_.ID -eq "6") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
