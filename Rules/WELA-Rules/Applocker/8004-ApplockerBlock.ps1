
function Add-Rule {
    $ruleName = "8004-ApplockerBlock";
    $detectedMessage = "detected Applocker block on DeepBlueCLI Rule";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 8004 -and $_.ProviderName -eq "Microsoft-Windows-AppLocker/EXE and DLL" }

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
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}