
$logo = @"
██╗    ██╗███████╗██╗      █████╗ 
██║    ██║██╔════╝██║     ██╔══██╗
██║ █╗ ██║█████╗  ██║     ███████║
██║███╗██║██╔══╝  ██║     ██╔══██║
╚███╔███╔╝███████╗███████╗██║  ██║
 ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
"@
function output-splash() {
    Write-Host ""
    foreach ($line in $logo -split "`n") {
        foreach ($char in $line.tochararray()) {
            if ($([int]$char) -le 9580 -and $([int]$char) -ge 9552) {
                Write-host -ForegroundColor Red $char -NoNewline
            }
            else {
                write-host -ForegroundColor blue $char -NoNewline
            }
        }
        Write-Host ""
    }
    Write-host "The Swiss Army Knife for Windows Event Logs!"
    write-host "                              by " -NoNewline
    write-host "Yamato Security" -ForegroundColor Yellow
}
output-splash