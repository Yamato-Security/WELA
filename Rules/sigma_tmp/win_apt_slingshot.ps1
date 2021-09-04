
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_apt_slingshot";
    $detectedMessage = "Detects the deactivation and disabling of the Scheduled defragmentation task as seen by Slingshot APT group"

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
