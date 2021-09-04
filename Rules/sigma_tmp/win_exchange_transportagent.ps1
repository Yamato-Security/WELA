Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Install-TransportAgent.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName MSExchange Management | where {($_.message -match ".*Install-TransportAgent.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
