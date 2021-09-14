
function Add-Rule {
    $ruleName = "4672-AdminAccountAccessAllAlerts";
    $detectedMessage = "Logon with SeDebugPrivilege (admin access)`nSpecial privileges assgned to new logons on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            if ($event.ProviderName -eq "Security" -and $event.id -eq 4672) {
                $eventXML = [xml]$event.ToXml();
                $username = $eventXML.Event.EventData.Data[1]."#text"
                $domain = $eventXML.Event.EventData.Data[2]."#text"
                $securityid = $eventXML.Event.EventData.Data[3]."#text"
                $privileges = $eventXML.Event.EventData.Data[4]."#text"
                if ($privileges -Match "SeDebugPrivilege") {
                    $result = "Username: $username`n"
                    $result += "Domain: $domain`n"
                    $result += "User SID: $securityid`n"
                    $result += "Privileges: $privileges"
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;
                    Write-Host $result
                }
            }
            
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}