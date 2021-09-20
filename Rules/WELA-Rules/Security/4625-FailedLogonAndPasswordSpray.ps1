
function Add-Rule {
    $ruleName = "4625_FailedLogonAndPasswordSpray";
    $detectedMessage = "High number of logon failures for one /multi account on DeepBlueCLI Rule";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $maxfailedlogons = 5

            $target = $event | where { $_.LogName -eq "Security" -and ($event.id -eq 4625) }
            if ($target) {
                $totalfailedaccounts = 0;
                $failedlogons = @{}
                foreach ($record in $target) {
                    $eventXML = [xml]$event.ToXml();
                    $username = $eventXML.Event.EventData.Data[5]."#text"
                    if ($failedlogons.ContainsKey($username)) {
                        $failedlogons[$username] += 1;
                    }
                    else {
                        $failedlogons[$username] = 1
                        $totalfailedaccounts += 1
                    }
                }
                $detectcount = 0
                foreach ($username in $failedlogons.Keys) {
                    if ($count -gt $maxfailedlogons) {
                        if ($detectcount -eq 0) {
                            Write-Host
                            Write-Host "Detected! RuleName:$ruleName";
                            Write-Host $detectedMessage;
                        }
                    
                        $result = "Username: $username`n"
                        $result += "Total logon failures: $count"
                        Write-Host $result    
                        $detectcount += 1
                    }
                }
                # Password spraying:
                if (($target.Count -gt $maxfailedlogons) -and ($target.Count -gt 1)) {
                    $result = "Total accounts: $totalfailedaccounts`n"
                    $result += "Total logon failures: $totalfailedlogons`n"

                    Write-Host 
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;                    
                    Write-host $result
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}