
function Add-Rule {
    $ruleName = "7036-SuspiciousServiceName";
    $detectedMessage = "detected Suspicious Service on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 7036 -and $_.ProviderName -eq "System" }

            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml();
                $servicename = $eventXML.Event.EventData.Data[0]."#text"
                $text = (Check-Regex $servicename 1)
                if ($text) {
                    $result = "Service name: $servicename`n"
                    $result += $text
                    
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;
                    Write-Output $result
                }
            }
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}