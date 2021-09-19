
function Add-Rule {
    $ruleName = "4674_HiddenServiceAttempt";
    $detectedMessage = "User requested to modify the Dynamic Access Control (DAC) permissions of a service, possibly to hide it from view on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )

            $target = $event | where { $_.ProviderName -eq "Security" -and ($event.id -eq 4674 -and $event.message -match "C:\WINDOWS\SYSTEM32\SERVICES.EXE" -and $event.message -match "write_dac") }
            if ($target) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
            }
            foreach ($record in $target) {
                $array = $event.message -split '\n' # Split each line of the message into an array
                $user = Remove-Spaces(($array[4] -split ':')[1])
                $service = Remove-Spaces(($array[11] -split ':')[1])
                $accessreq = Remove-Spaces(($array[19] -split ':')[1])
                $result = "User: $user`n"
                $result += "Target service: $service`n"
                $result += "Desired Access: $accessreq`n"
                Write-host $result
            }
        };
        . Search-DetectableEvents $args[0]0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}