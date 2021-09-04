
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_powershell_script_installed_as_service";
    $detectedMessage = "Detects powershell script installed as a Service"

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
