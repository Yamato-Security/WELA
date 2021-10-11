# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "15") -and  -not (($_.message -match "Imphash.*00000000000000000000000000000000") -or (-not Imphash="*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_ads_executable";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_ads_executable";
            $detectedMessage = "Detects the creation of an ADS data stream that contains an executable (non-empty imphash)";
            $result = $event |  where { (($_.ID -eq "15") -and -not (($_.message -match "Imphash.*00000000000000000000000000000000") -or (-not $_.message -eq "Imphash.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
