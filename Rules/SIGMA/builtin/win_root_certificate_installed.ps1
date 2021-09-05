
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_root_certificate_installed";
    $detectedMessage = "Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers."

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
