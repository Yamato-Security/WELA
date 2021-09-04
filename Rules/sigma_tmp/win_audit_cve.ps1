Get-WinEvent -LogName Application | where {($_.message -match "Source.*Microsoft-Windows-Audit-CVE") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
