Get-WinEvent -LogName System | where {($_.ID -eq "1033" -and $_.message -match "Source.*Microsoft-Windows-DHCP-Server") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
