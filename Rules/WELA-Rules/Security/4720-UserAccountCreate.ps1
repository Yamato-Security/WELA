
function Add-Rule {
    $ruleName = "4720-UserAccountCreate";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "4720-UserAccountCreate";
            $detectedMessage = "User account create on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 4720 -and $_.LogName -eq "Security" }

            if ($target) {
                foreach ($record in $target) {
                    $eventXML = [xml]$event.ToXml();
                    $username = $eventXML.Event.EventData.Data[0]."#text"
                    $securityid = $eventXML.Event.EventData.Data[2]."#text"
                    $result = "New User Created"
                    $result += "Username: $username`n"
                    $result += "User SID: $securityid`n"
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;
                    Write-Host $result
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}