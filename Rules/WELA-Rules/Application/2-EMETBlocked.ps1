# Get-WinEvent -LogName Security  where {($_.ID -eq "4688" | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    $ruleName = "2-EMETBlocked";
    $detectedMessage = "detected EMET blocked on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 2 -and $_.ProviderName -eq "Application" }

            foreach ($record in $target) {
                if ($record.message) {
                    $array = $event.message -split '\n' # Split each line of the message into an array
                    $text = $array[0]
                    $application = Remove-Spaces($array[3])
                    $command = $application -Replace "^Application: ", ""
                    $username = Remove-Spaces($array[4])
                    $result = "$text`n"
                    $reuslt += "command: $command`n"
                    $result += "$username`n" 
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;
                    Write-host $result
    
                }
                else {
                    Write-Host "Warning: EMET Message field is blank. Install EMET locally to see full details of this alert"
                }
            }
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}