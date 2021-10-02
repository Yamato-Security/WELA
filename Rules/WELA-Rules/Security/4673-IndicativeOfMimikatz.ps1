
function Add-Rule {
    $ruleName = "4673_IndicativeOfMimikatz";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "4673_IndicativeOfMimikatz";
            $detectedMessage = "Potentially indicative of Mimikatz, multiple sensitive privilege calls have been made on DeepBlueCLI Rule";        
            $target = $event | where { $_.LogName -eq "Security" -and ($_.id -eq 4673) }
            $maxtotalsensprivuse = 4
            $resultoutput = @{}

            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml();
                $username = $eventXML.Event.EventData.Data[1]."#text"
                $domainname = $eventXML.Event.EventData.Data[2]."#text"
                $key = "$username\\$domainname"
                if (!$resultoutput.ContainsKey($key)) {
                    $result = Create-Obj $record $LogFile
                    $result.Results = "Username: $username`nDomain Name:$domainname`n"
                    $resultoutput.Add($key, $result)
                }
            }
            if ($target.Count -ge $maxtotalsensprivuse) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                foreach ($result in $resultoutput.Values) {
                    Write-Output $result | Format-Table * -Wrap;
                    Write-Host
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}