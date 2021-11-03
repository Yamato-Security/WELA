
function Add-Rule {
    $ruleName = "2-EMETBlocked";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 2 -and $_.LogName -eq "Application" }
            $ruleName = "2-EMETBlocked";
            $detectedMessage = "detected EMET blocked on DeepBlueCLI Rule";
            foreach ($record in $target) {
                if ($record.message) {
                    $result = Create-Obj $record $LogFile
                    $array = $record.message -split '\n' # Split each line of the message into an array
                    $text = $array[0]
                    $application = Remove-Spaces($array[3])
                    $command = $application -Replace "^Application: ", ""
                    $username = Remove-Spaces($array[4])
                    $result.Message = $detectedMessage
                    $result.Command = "$command"
                    $result.Results = "$text`n"
                    $result.Results += "$username`n" 
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;
                    Write-Output $result;
                    Write-Output ""; 
                }
                else {
                    Write-Output "Warning: EMET Message field is blank. Install EMET locally to see full details of this alert"
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