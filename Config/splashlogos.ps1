
$logo1 = @"
██╗    ██╗███████╗██╗      █████╗ 
██║    ██║██╔════╝██║     ██╔══██╗
██║ █╗ ██║█████╗  ██║     ███████║
██║███╗██║██╔══╝  ██║     ██╔══██║
╚███╔███╔╝███████╗███████╗██║  ██║
 ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
"@

$logo2 = @"
W     W EEEE L     AA  
W     W E    L    A  A 
W  W  W EEE  L    AAAA 
 W W W  E    L    A  A 
  W W   EEEE LLLL A  A
"@

$logo3 = @"
db   d8b   db d88888b db       .d8b.  
88   I8I   88 88'     88      d8' `8b 
88   I8I   88 88ooooo 88      88ooo88 
Y8   I8I   88 88~~~~~ 88      88~~~88 
`8b  d8'8b d8' 88.     88booo. 88   88 
 `8b8'' `8d8''  Y88888P Y88888P YP   YP 
"@

$logo4 = @"
888       888 8888888888 888             d8888 
888   o   888 888        888            d88888 
888  d8b  888 888        888           d88P888 
888 d888b 888 8888888    888          d88P 888 
888d88888b888 888        888         d88P  888 
88888P Y88888 888        888        d88P   888 
8888P   Y8888 888        888       d8888888888 
888P     Y888 8888888888 88888888 d88P     888
"@

$logo5 = @"
_             _  _  _  _  _  _  _                    _          
(_)           (_)(_)(_)(_)(_)(_)(_)                 _(_)_        
(_)           (_)(_)            (_)               _(_) (_)_      
(_)     _     (_)(_) _  _       (_)             _(_)     (_)_    
(_)   _(_)_   (_)(_)(_)(_)      (_)            (_) _  _  _ (_)   
(_)  (_) (_)  (_)(_)            (_)            (_)(_)(_)(_)(_)   
(_)_(_)   (_)_(_)(_) _  _  _  _ (_) _  _  _  _ (_)         (_)   
  (_)       (_)  (_)(_)(_)(_)(_)(_)(_)(_)(_)(_)(_)         (_) 
"@

$logo6 = @"
▄▄▌ ▐ ▄▌▄▄▄ .▄▄▌   ▄▄▄· 
██· █▌▐█▀▄.▀·██•  ▐█ ▀█ 
██▪▐█▐▐▌▐▀▀▪▄██▪  ▄█▀▀█ 
▐█▌██▐█▌▐█▄▄▌▐█▌▐▌▐█ ▪▐▌
 ▀▀▀▀ ▀▪ ▀▀▀ .▀▀▀  ▀  ▀                            
"@

$logo7 = @"
Yb        dP 8888 8       db    
 Yb  db  dP  8www 8      dPYb   
  YbdPYbdP   8    8     dPwwYb  
   YP  YP    8888 8888 dP    Yb
"@

$logo8 = @"
,ggg,      gg      ,gg   ,ggggggg,        ,gggg,             ,ggg,  
dP""Y8a     88     ,8P  ,dP""""""Y8b      d8" "8I            dP""8I  
Yb, `88     88     d8'  d8'    a  Y8      88  ,dP           dP   88  
 `"  88     88     88   88     "Y8P'   8888888P"           dP    88  
     88     88     88   `8baaaa           88              ,8'    88  
     88     88     88  ,d8P""""           88              d88888888  
     88     88     88  d8"           ,aa,_88        __   ,8"     88  
     Y8    ,88,    8P  Y8,          dP" "88P       dP"  ,8P      Y8  
      Yb,,d8""8b,,dP   `Yba,,_____, Yb,_,d88b,,_   Yb,_,dP       `8b,
       "88"    "88"      `"Y8888888  "Y8P"  "Y88888 "Y8P"         `Y8
"@

$logo9 = @"
oooo     oooo ooooooooooo ooooo            o      
 88   88  88   888    88   888            888     
  88 888 88    888ooo8     888           8  88    
   888 888     888    oo   888      o   8oooo88   
    8   8     o888ooo8888 o888ooooo88 o88o  o888o 
"@

$logo10 = @"                                       
@@@  @@@  @@@ @@@@@@@@ @@@       @@@@@@  
@@!  @@!  @@! @@!      @@!      @@!  @@@ 
@!!  !!@  @!@ @!!!:!   @!!      @!@!@!@! 
 !:  !!:  !!  !!:      !!:      !!:  !!! 
  ::.:  :::   : :: ::  : ::.: :  :   : :
"@

$logos = $logo1, $logo2, $logo3, $logo4, $logo5, $logo6, $logo7,  $logo8,  $logo9,  $logo10
$logo = Get-Random -InputObject $logos


function output-splash() {
    Write-Host ""
    foreach ($line in $logo -split "`n") {
        foreach ($char in $line.tochararray()) {
            if ($([int]$char) -le 9580 -and $([int]$char) -ge 9552) {
                Write-host -ForegroundColor Red $char -NoNewline
            }
            else {
                write-host -ForegroundColor Red $char -NoNewline
            }
        }
        Write-Host ""
    }
    write-host 
    Write-host "The Swiss Army Knife for Windows Event Logs!"
    write-host "                              by " -NoNewline
    write-host "Yamato Security" -ForegroundColor Yellow
}
output-splash