
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_powershell_web_request";
    $detectedMessage = "Detects the use of various web request methods (including aliases) via Windows PowerShell"

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
