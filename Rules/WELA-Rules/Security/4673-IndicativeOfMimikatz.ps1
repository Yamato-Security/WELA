﻿
function Add-Rule {
    $ruleName = "4673_IndicativeOfMimikatz";
    $detectedMessage = "Potentially indicative of Mimikatz, multiple sensitive privilege calls have been made on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )

            $target = $event | where { $_.ProviderName -eq "Security" -and ($event.id -eq 4673) }
            $maxtotalsensprivuse = 4
            $resultoutput = @{}

            foreach ($record in $target) {
                $eventXML = [xml]$event.ToXml();
                $username = $eventXML.Event.EventData.Data[1]."#text"
                $domainname = $eventXML.Event.EventData.Data[2]."#text"
                $key = "$username\\$domainname"
                if (!$resultoutput.ContainsKey($key)) {
                    $resultoutput.Add($key, "Username: $username`nDomain Name:$domainname`n")
                }
            }
            if ($target.Count -ge $maxtotalsensprivuse) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                foreach ($result in $resultoutput.Values) {
                    Write-Host $result
                }
            }
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}