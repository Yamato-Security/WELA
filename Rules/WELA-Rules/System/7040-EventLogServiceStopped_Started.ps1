
function Add-Rule {
    $ruleName = "7040-EventLogServiceStopped/Started";
    $detectedMessage = "detected event log serice stopped/started on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 7040 -and $_.ProviderName -eq "System" }

            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml();
                $servicename = $eventXML.Event.EventData.Data[0]."#text"
                $action = $eventXML.Event.EventData.Data[1]."#text"
                if ($servicename -ccontains "Windows Event Log") {
                    $result = "Service name: $servicename`n"
                    $result += $text
                    if ($action -eq "disabled") {
                        $result += "Selective event log manipulation may follow this event."
                    }
                    elseIf ($action -eq "auto start") {
                        $result += "Selective event log manipulation may precede this event."
                    }
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;
                    Write-host $result
                }
            }
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}