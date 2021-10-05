
function Add-Rule {
    $ruleName = "8004-ApplockerBlock";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $ruleName = "8004-ApplockerBlock";
            $detectedMessage = "detected Applocker block on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 8004 -and $_.LogName -eq "Microsoft-Windows-AppLocker/EXE and DLL" }

            if ($target) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
            }
            foreach ($record in $target) {
                Write-Host $result;
Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}