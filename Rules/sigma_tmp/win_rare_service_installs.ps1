Get-WinEvent -LogName System | where {($_.ID -eq "7045") }  | group-object ServiceFileName | where { $_.count -lt 5 } | select name,count | sort -desc
