# Get-WinEvent -LogName System | where {($_.ID -eq "7045") }  | group-object ServiceFileName | where { $_.count -lt 5 } | select name,count | sort -desc

function Add-Rule {

    $ruleName = "win_rare_service_installs";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_rare_service_installs";
            $detectedMessage = "Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services";
            $result = $event |  where { ($_.ID -eq "7045") } | group-object ServiceFileName | where { $_.count -lt 5 } | select name, count | sort -desc;
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
