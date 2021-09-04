Get-WinEvent -LogName Microsoft-Windows-NTLM/Operational | where {($_.ID -eq "8001" -and $_.message -match "TargetName.*TERMSRV.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
