
function Add-Rule {
    $ruleName = "1102_AuditLogFileClear";
    
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $ruleName = "1102_AuditLogFileClear";
            $detectedMessage = "The Audit log was cleared on DeepBlueCLI Rule";

            $target = $event | where { $_.LogName -eq "Security" -and $_.id -eq 1102 }
            if ($target) {
                foreach ($record in $target) {
                    $array = $record.message -split '\n' # Split each line of the message into an array
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
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}