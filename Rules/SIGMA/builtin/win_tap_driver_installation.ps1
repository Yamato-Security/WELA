
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_tap_driver_installation";
    $detectedMessage = "Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques"

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
