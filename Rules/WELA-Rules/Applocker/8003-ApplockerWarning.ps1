
function Add-Rule {
    $ruleName = "8003-ApplockerWarning";
    $detectedMessage = "detected Applocker warning on DeepBlueCLI Rule";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 8003 -and $_.LogName -eq "Microsoft-Windows-AppLocker/EXE and DLL" }

            if ($target) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
            }
            foreach ($record in $target) {
                $result = $record.message
                Write-host $result
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}