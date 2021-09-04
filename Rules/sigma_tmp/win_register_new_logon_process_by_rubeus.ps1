Get-WinEvent -LogName Security | where {($_.ID -eq "4611" -and $_.message -match "LogonProcessName.*User32LogonProcesss") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
