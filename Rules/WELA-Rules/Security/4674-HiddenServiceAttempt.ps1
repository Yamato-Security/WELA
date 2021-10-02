
function Add-Rule {
    $ruleName = "4674_HiddenServiceAttempt";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "4674_HiddenServiceAttempt";
            $detectedMessage = "User requested to modify the Dynamic Access Control (DAC) permissions of a service, possibly to hide it from view on DeepBlueCLI Rule";
            $target = $event | where { $_.LogName -eq "Security" -and ($_.id -eq 4674 -and $_.message.ToUpper() -match "C:\WINDOWS\SYSTEM32\SERVICES.EXE" -and $_.message.ToUpper() -match "write_dac") }
            if ($target) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
            }
            foreach ($record in $target) {
                $array = $record.message -split '\n' # Split each line of the message into an array
                $user = Remove-Spaces(($array[4] -split ':')[1])
                $service = Remove-Spaces(($array[11] -split ':')[1])
                $accessreq = Remove-Spaces(($array[19] -split ':')[1])
                $result = Create-Obj $record $LogFile
                $result.message = $detectedMessage
                $result.Results = "User: $user`n"
                $result.Results += "Target service: $service`n"
                $result.Results += "Desired Access: $accessreq`n"
                Write-Output $result | Format-Table * -Wrap;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}