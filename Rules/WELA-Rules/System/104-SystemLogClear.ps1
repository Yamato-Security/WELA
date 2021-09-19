
function Add-Rule {
    $ruleName = "104-SystemLogClear";
    $detectedMessage = "detected system log cleared on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 104 -and $_.ProviderName -eq "System" }

            if ($target) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
            }
            foreach ($record in $target) {
                $result = $record.message
                Write-hoss $result
            }
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}