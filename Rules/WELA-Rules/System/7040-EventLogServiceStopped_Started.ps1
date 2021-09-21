
function Add-Rule {
    $ruleName = "7040-EventLogServiceStopped/Started";
    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "7040-EventLogServiceStopped/Started";
            $detectedMessage = "detected event log serice stopped/started on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 7040 -and $_.LogName -match "System" }
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
                    Write-Host $result;
Write-Host
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}