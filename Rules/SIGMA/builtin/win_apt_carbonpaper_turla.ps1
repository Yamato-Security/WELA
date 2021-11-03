# Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and ($_.message -match "srservice" -or $_.message -match "ipvpn" -or $_.message -match "hkmsvc")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_carbonpaper_turla";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_carbonpaper_turla";
            $detectedMessage = "This method detects a service install of malicious services mentioned in Carbon Paper - Turla report by ESET";
            $result = $event |  where { ($_.ID -eq "7045" -and ($_.message -match "srservice" -or $_.message -match "ipvpn" -or $_.message -match "hkmsvc")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
            
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
