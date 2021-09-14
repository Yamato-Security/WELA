
function Add-Rule {
    $ruleName = "4720-UserAccountCreate";
    $detectedMessage = "User account create on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            if ($event.ProviderName -eq "Security" -and $event.id -eq 4720) {
                $eventXML = [xml]$event.ToXml();
                $username = $eventXML.Event.EventData.Data[0]."#text"
                $securityid = $eventXML.Event.EventData.Data[2]."#text"
                $result = "New User Created"
                $result = "Username: $username`n"
                $result += "User SID: $securityid`n"
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result
            }
            
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}