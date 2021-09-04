
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_regsvr32_network_activity";
    $detectedMessage = "Detects network connections and DNS queries initiated by Regsvr32.exe"

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
