
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_mal_creddumper";
    $detectedMessage = "Detects well-known credential dumping tools execution via service execution events"

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
