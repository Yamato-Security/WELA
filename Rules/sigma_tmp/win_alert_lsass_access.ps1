Get-WinEvent | where {($_.ID -eq "1121" -and $_.message -match "Path.*.*\\lsass.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
