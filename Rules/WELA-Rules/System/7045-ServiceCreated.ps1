
function Add-Rule {
    $ruleName = "7045-ProcessCreated";
    $detectedMessage = "detected ProcessCreate on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 7045 -and $_.ProviderName -eq "System" }

            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml();
                # A service was installed in the system.
                $servicename = $eventXML.Event.EventData.Data[0]."#text"
                $commandline = $eventXML.Event.EventData.Data[1]."#text"
                # Check for suspicious service name
                $text = (Check-Regex $servicename 1)
                if ($text) {
                    $result = "Service name: $servicename`n"
                    $result += $text 
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;
                    Write-host $result
                }
                # Check for suspicious cmd
                if ($commandline) {
                    $servicecmd = 1 # CLIs via service creation get extra checks 
                    $result = Check-Command -EventID 7045 -servicecmd $servicecmd
                    if ($result) {
                        Write-Host
                        Write-Host "Detected! RuleName:$ruleName";
                        Write-Host $detectedMessage;
                        Write-Host $result
                    }
                }
            }
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}