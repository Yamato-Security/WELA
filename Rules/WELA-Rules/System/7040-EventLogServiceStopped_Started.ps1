
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
                    $result = Create-Obj $record $LogFile
                    $result.Results = "Service name: $servicename`n"
                    $result.Results += $text
                    if ($action -eq "disabled") {
                        $result.Message += "Selective event log manipulation may follow this event."
                    }
                    elseIf ($action -eq "auto start") {
                        $result.Message += "Selective event log manipulation may precede this event."
                    }
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
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