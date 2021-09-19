
function Add-Rule {
    $ruleName = "7030-InteractiveServiceWarning";
    $detectedMessage = "detected Interactive service warning on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 7030 -and $_.ProviderName -eq "System" }

            if ($target) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
            }
            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml();
                $servicename = $eventXML.Event.EventData.Data."#text"
                $result = "Service name: $servicename`n"
                $result += "Malware (and some third party software) trigger this warning"
                # Check for suspicious service name
                $result += (Check-Regex $servicename 1)
                Write-host $result
            }
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}