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
function Get-WinEventWithFilter {
    param(
        $WinEventFilter,
        $RemoteComputerInfo
    )
    $logs = $null

    if ( $RemoteComputerInfo.RemoteLiveAnalysis -eq $true ) {
        $logs = Get-WinEvent -ComputerName $RemoteComputerInfo.Computername -Credential $RemoteComputerInfo.Credential -FilterHashtable $WinEventFilter -Oldest -ErrorAction SilentlyContinue
    }
    else {
        $logs = Get-WinEvent -FilterHashtable $WinEventFilter -Oldest -ErrorAction SilentlyContinue
    }

    if ($LASTEXITCODE -ne 0) {
        if ($logs) {
            Write-Host $Warn_GetEvent -ForegroundColor Black -BackgroundColor Yellow
        }
        else {
            Write-Host $Info_GetEventNoMatch -ForegroundColor Green
        }
    }
    return $logs
}

function Show-Contributors {
    Write-Host 
    Write-Host $Show_Contributors1 -ForegroundColor Red 
    Write-Host $Show_Contributors2 -ForegroundColor Cyan
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


# following check function in DeepBlueCLI.

$minlength = 1000 # Minimum length of command line to alert
# Load cmd match regexes from csv file, ignore comments
$regexes = Get-Content ".\Config\regexes.txt" | Select-String '^[^#]' | ConvertFrom-Csv
# Load cmd whitelist regexes from csv file, ignore comments
$whitelist = Get-Content ".\Config\whitelist.txt" | Select-String '^[^#]' | ConvertFrom-Csv 

# Custom reporting object:
function Create-Obj {
    param($event, $logname)
    if ($event) {
        $obj = [PSCustomObject]@{
            Date    = $event.TimeCreated
            Log     = $logname
            EventID = $event.id
            Message = $event.message
            Results = ""
            Command = ""
            Decoded = ""
        }
    }
    else {
        $obj = [PSCustomObject]@{
            Date    = ""
            Log     = $logname
            EventID = ""
            Message = ""
            Results = ""
            Command = ""
            Decoded = ""
        }
    }
    return $obj
}

function Check-Command() {

    Param(
        $EventID,
        $commandline,
        $creator,
        $servicecmd = 0,
        $obj
    )

    $text = ""
    $base64 = ""
    # Check to see if command is whitelisted
    foreach ($entry in $whitelist) {
        if ($commandline -Match $entry.regex) {
            # Command is whitelisted, return nothing
            return
        }
    }
    if ($commandline.length -gt $minlength) {
        $text += "Long Command Line: greater than $minlength bytes`n"
    }
    $text += (Check-Obfu $commandline)
    $text += (Check-Regex $commandline 0)
    $text += (Check-Creator $commandline $creator)
    # Check for base64 encoded function, decode and print if found
    # This section is highly use case specific, other methods of base64 encoding and/or compressing may evade these checks
    if ($commandline -Match "\-enc.*[A-Za-z0-9/+=]{100}") {
        $base64 = $commandline -Replace "^.* \-Enc(odedCommand)? ", ""
    }
    ElseIf ($commandline -Match ":FromBase64String\(") {
        $base64 = $commandline -Replace "^.*:FromBase64String\(\'*", ""
        $base64 = $base64 -Replace "\'.*$", ""
    }
    if ($base64) {
        if ($commandline -Match "Compression.GzipStream.*Decompress") {
            # Metasploit-style compressed and base64-encoded function. Uncompress it.
            $decoded = New-Object IO.MemoryStream(, [Convert]::FromBase64String($base64))
            $uncompressed = (New-Object IO.StreamReader(((New-Object IO.Compression.GzipStream($decoded, [IO.Compression.CompressionMode]::Decompress))), [Text.Encoding]::ASCII)).ReadToEnd()
            $obj.Decoded = $uncompressed
            $text += "Base64-encoded and compressed function`n"
        }
        else {
            $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64))
            $obj.Decoded = $decoded
            $text += "Base64-encoded function`n"
            $text += (Check-Obfu $decoded)
            $text += (Check-Regex $decoded 0)
        }
    }
    if ($text) {
        if ($servicecmd) {
            $obj.Message = "Suspicious Service Command"
            $obj.Results = "Service name: $servicename`n"
        }
        Else {
            $obj.Message = "Suspicious Command Line"
        }
        $obj.Command = $commandline
        $obj.Results += $text
        $obj.EventID = $EventID
        return $obj;
    }
    return $null;
}


function Check-Regex($string, $type) {
    $regextext = "" # Local variable for return output
    foreach ($regex in $regexes) {
        if ($regex.Type -eq $type) {
            # Type is 0 for Commands, 1 for services. Set in regexes.csv
            if ($string -Match $regex.regex) {
                $regextext += $regex.String + "`n"
            }
        }
    }
    #if ($regextext){ 
    #   $regextext = $regextext.Substring(0,$regextext.Length-1) # Remove final newline.
    #}
    return $regextext
}

function Check-Obfu($string) {
    # Check for special characters in the command. Inspired by Invoke-Obfuscation: https://twitter.com/danielhbohannon/status/778268820242825216
    #
    $obfutext = ""       # Local variable for return output
    if (!$string) {
        return $null
    }
    $minpercent = .65
    $maxbinary = .50
    $lowercasestring = $string.ToLower()
    $length = $lowercasestring.length
    $noalphastring = $lowercasestring -replace "[a-z0-9/\;:|.]"
    $nobinarystring = $lowercasestring -replace "[01]" # To catch binary encoding
    # Calculate the percent alphanumeric/common symbols
    if ($length -gt 0) {
        $percent = (($length - $noalphastring.length) / $length)
        # Adjust minpercent for very short commands, to avoid triggering short warnings
        if (($length / 100) -lt $minpercent) { 
            $minpercent = ($length / 100) 
        }
        if ($percent -lt $minpercent) {
            $percent = "{0:P0}" -f $percent      # Convert to a percent
            $obfutext += "Possible command obfuscation: only $percent alphanumeric and common symbols`n"
        }
        # Calculate the percent of binary characters  
        $percent = (($nobinarystring.length - $length / $length) / $length)
        $binarypercent = 1 - $percent
        if ($binarypercent -gt $maxbinary) {
            #$binarypercent = 1-$percent
            $binarypercent = "{0:P0}" -f $binarypercent      # Convert to a percent
            $obfutext += "Possible command obfuscation: $binarypercent zeroes and ones (possible numeric or binary encoding)`n"
        }
    }
    return $obfutext
}

function Check-Creator($command, $creator) {
    $creatortext = ""  # Local variable for return output
    if ($creator) {
        if ($command -Match "powershell") {
            if ($creator -Match "PSEXESVC") {
                $creatortext += "PowerShell launched via PsExec: $creator`n"
            }
            ElseIf ($creator -Match "WmiPrvSE") {
                $creatortext += "PowerShell launched via WMI: $creator`n"
            }
        }
    }
    return $creatortext
}

function Remove-Spaces($string) {
    # Changes this:   Application       : C:\Program Files (x86)\Internet Explorer\iexplore.exe
    #      to this: Application: C:\Program Files (x86)\Internet Explorer\iexplore.exe
    $string = $string.trim() -Replace "\s+:", ":"
    return $string
}

function Get-RemoteComputerInfo {
    $Computername = Read-Host $remoteAnalysis_getComputername
    $trustedhosts = Get-Item WSMan:\localhost\client\trustedhosts

    If ($Computername -contains $trustedhosts.Value -or $trustedhosts.Value -eq "*") {
        $creds = Get-Credential -Message $remoteAnalysis_getCredential
        $Test = Test-WSMan -ComputerName $Computername -Credential $creds -Authentication Negotiate

        If ( $Test -eq $NULL ) {
            Write-Host ""
            write-host $Error_remoteAnalysis_FailedTestWSMan -ForegroundColor White -BackgroundColor Red
            write-host $Warn_remoteAnalysis_Stopped_WinRMservice -ForegroundColor Black -BackgroundColor Yellow
            write-host $Warn_remoteAnalysis_wrongRemoteComputerInfo -ForegroundColor Black -BackgroundColor Yellow
            Write-Host ""
            Exit
        }
        
        $RemoteComputerInfo = @{
            "RemoteLiveAnalysis" = $True;
            "Computername"       = $Computername;
            "Credential"         = $creds
        }
        return $RemoteComputerInfo
    }

    else {
        Write-Host ""
        Write-Host $Error_remoteAnalysis_UnregisteredComputername -ForegroundColor White -BackgroundColor Red
        Write-Host ""
        Exit
    }
}