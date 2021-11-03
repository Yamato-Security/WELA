
function Add-Rule {
    $ruleName = "4674_HiddenServiceAttempt";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "4674_HiddenServiceAttempt";
            $detectedMessage = "User requested to modify the Dynamic Access Control (DAC) permissions of a service, possibly to hide it from view on DeepBlueCLI Rule";
            $target = $event | where { $_.LogName -eq "Security" -and ($_.id -eq 4674) }
            if ($target) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
            }
            foreach ($record in $target) {
                $array = $record.message -split '\n' # Split each line of the message into an array
                $user = Remove-Spaces(($array[4] -split ':')[1])
                $service = Remove-Spaces(($array[11] -split ':')[1])
                $application = Remove-Spaces(($array[16] -split ':	')[1])
                $accessreq = Remove-Spaces(($array[19] -split ':')[1])
                if ($application.ToUpper() -eq "C:\WINDOWS\SYSTEM32\SERVICES.EXE" -and $accessreq.ToUpper() -eq "WRITE_DAC") {
                    $result = Create-Obj $record $LogFile
                    $result.message = $detectedMessage
                    $result.results = "User: $user`n"
                    $result.results += "Target service: $service`n"
                    $result.results += "Desired Access: $accessreq`n"
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