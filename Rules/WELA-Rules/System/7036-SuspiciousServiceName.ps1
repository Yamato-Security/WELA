
function Add-Rule {
    $ruleName = "7036-SuspiciousServiceName";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "7036-SuspiciousServiceName";
            $detectedMessage = "detected Suspicious Service on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 7036 -and $_.LogName -eq "System" }

            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml();
                $servicename = $eventXML.Event.EventData.Data[0]."#text"
                $text = (Check-Regex $servicename 1)
                if ($text) {
                    $result = Create-Obj $record $LogFile
                    $result.Message = $detectedMessage
                    $result.Results = "Service name: $servicename`n"
                    $result.Results += $text
                    
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;
                    Write-Output $result;
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