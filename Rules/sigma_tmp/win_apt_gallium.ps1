
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_apt_gallium";
    $detectedMessage = "Detects artefacts associated with activity group GALLIUM - Microsoft Threat Intelligence Center indicators released in December 2019."

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
