
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_advanced_ip_scanner";
    $detectedMessage = "Detects the use of Advanced IP Scanner. Seems to be a popular tool for ransomware groups."

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