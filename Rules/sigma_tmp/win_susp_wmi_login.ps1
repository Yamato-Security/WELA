Get-WinEvent -LogName Security | where {($_.ID -eq "4624" -and $_.message -match "ProcessName.*.*\\WmiPrvSE.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
