
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "powershell_powercat";
    $detectedMessage = "Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | !firstpipe!
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
