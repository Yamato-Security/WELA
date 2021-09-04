
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_winrm_AWL_bypass";
    $detectedMessage = "Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)"

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
