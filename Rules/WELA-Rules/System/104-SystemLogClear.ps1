
function Add-Rule {
    $ruleName = "104-SystemLogClear";
    $detectedMessage = "detected system log cleared on DeepBlueCLI Rule";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "104-SystemLogClear";
            $detectedMessage = "detected system log cleared on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 104 -and $_.LogName -eq "System" }

            if ($target) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
            }
            foreach ($record in $target) {
                $result = $record.message
                Write-Host $result
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}