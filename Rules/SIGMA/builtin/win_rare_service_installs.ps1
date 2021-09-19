# Get-WinEvent -LogName System | where {($_.ID -eq "7045") }  | group-object ServiceFileName | where { $_.count -lt 5 } | select name,count | sort -desc

function Add-Rule {

    $ruleName = "win_rare_service_installs";
    $detectedMessage = "Detects rare service installs that only appear a few times per time frame and could reveal password dumpers, backdoor installs or other types of malicious services";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "7045") } | group-object ServiceFileName | where { $_.count -lt 5 } | select name,count | sort -desc;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
