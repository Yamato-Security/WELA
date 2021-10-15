
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
                    $result = Create-Obj $record $LogFile
                    $array = $record.message -split '\n' # Split each line of the message into an array
                    $user = Remove-Spaces($array[3])
                    $result.Message = $detectedMessage
                    $eventTimestampString = $record.TimeCreated.ToString($DateFormat)
                    $result.Results = "User:$user"
                    Write-Output ""; 
                    Write-Output "$eventTimestampString Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;
                    Write-Output $result;
                    Write-Output "";
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}