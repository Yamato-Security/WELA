
function Add-Rule {
    $ruleName = "7030-InteractiveServiceWarning";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "7030-InteractiveServiceWarning";
            $detectedMessage = "detected Interactive service warning on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 7030 -and $_.LogName -eq "System" }

            if ($target) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
            }
            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml();
                $servicename = $eventXML.Event.EventData.Data."#text"
                $result = Create-Obj $record $Logfile
                $result.Results = "Service name: $servicename`n"
                $result.Results += "Malware (and some third party software) trigger this warning"
                # Check for suspicious service name
                $result.Results += (Check-Regex $servicename 1)
                Write-Output $result | Format-Table * -Wrap;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}