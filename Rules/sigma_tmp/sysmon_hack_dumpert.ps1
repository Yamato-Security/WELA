
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_hack_dumpert";
    $detectedMessage = "Detects the use of Dumpert process dumper, which dumps the lsass.exe process memory"

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
