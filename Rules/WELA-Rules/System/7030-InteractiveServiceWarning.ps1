
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
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
            }
            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml();
                $servicename = $eventXML.Event.EventData.Data."#text"
                $result = Create-Obj $record $Logfile
                $result.Results = "Service name: $servicename`n"
                $result.Results += "Malware (and some third party software) trigger this warning"
                # Check for suspicious service name
                $result.Results += (Check-Regex $servicename 1)
                Write-Output $result;
                Write-Output ""; 
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