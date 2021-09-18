
function Add-Rule {
    $ruleName = "1102_AuditLogFileClear";
    $detectedMessage = "The Audit log was cleared on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )

            $target = $event | where { $event.ProviderName -eq "Security" -and $event.id -eq 1102 }
            if ($target) {
                foreach ($record in $target) {
                    $array = $event.message -split '\n' # Split each line of the message into an array
                    $user = Remove-Spaces($array[3])
                    $result = "The Audit log was cleared."
                    $eventTimestampString = $record.TimeCreated.ToString($DateFormat)
                    $result += $user
                    Write-Host
                    Write-Host "$eventTimestampString Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;
                    Write-Host $result    
                }
            }
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}