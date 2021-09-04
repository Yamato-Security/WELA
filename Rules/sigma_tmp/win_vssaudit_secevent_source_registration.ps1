Get-WinEvent -LogName Security | where {($_.message -match "AuditSourceName.*VSSAudit" -and ($_.ID -eq "4904" -or $_.ID -eq "4905")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
