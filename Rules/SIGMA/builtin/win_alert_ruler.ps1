# Get-WinEvent -LogName Security | where {(((($_.ID -eq "4776") -and $_.message -match "Workstation.*RULER") -or (($_.ID -eq "4624" -or $_.ID -eq "4625") -and $_.message -match "WorkstationName.*RULER"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_alert_ruler";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_alert_ruler";
            $detectedMessage = "This events that are generated when using the hacktool Ruler by Sensepost";
            $result = $event |  where { (((($_.ID -eq "4776") -and $_.message -match "Workstation.*RULER") -or (($_.ID -eq "4624" -or $_.ID -eq "4625") -and $_.message -match "WorkstationName.*RULER"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
