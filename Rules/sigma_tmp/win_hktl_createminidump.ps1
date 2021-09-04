
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_hktl_createminidump";
    $detectedMessage = "Detects the use of CreateMiniDump hack tool used to dump the LSASS process memory for credential extraction on the attacker's machine"

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
