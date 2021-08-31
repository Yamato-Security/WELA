<#

.DESCRIPTION
WELA utils funciton


.LINK
https://github.com/yamatosecurity
#>

# Yamato Event Analyzer (YEA) Security event timeline generator
# Zach Mathis, Yamatosecurity founder
# Twitter: @yamatosecurity
# https://yamatosecurity.connpass.com/
# 
# Inspired by Eric Conrad's DeepBlueCLI (https://github.com/sans-blue-team/DeepBlueCLI)
# Much help from the Windows Event Log Analysis Cheatsheets by Steve Anson (https://www.forwarddefense.com/en/article/references-pdf)
# and event log info from www.ultimatewindowssecurity.com


#Functions:
function Show-Contributors {
    Write-Host 
    Write-Host $Show_Contributors -ForegroundColor Cyan
    Write-Host
}
Function Format-FileSize {
    Param ([int]$size)
    If ($size -gt 1TB) { [string]::Format("{0:0.00} TB", $size / 1TB) }
    ElseIf ($size -gt 1GB) { [string]::Format("{0:0.00} GB", $size / 1GB) }
    ElseIf ($size -gt 1MB) { [string]::Format("{0:0.00} MB", $size / 1MB) }
    ElseIf ($size -gt 1KB) { [string]::Format("{0:0.00} kB", $size / 1KB) }
    ElseIf ($size -gt 0) { [string]::Format("{0:0.00} B", $size) }
    Else { "" }
}

function Check-Administrator {  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

