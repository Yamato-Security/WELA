
function Add-Rule {
    $ruleName = "4728_4732_4756-AddedUserAdministratorsGroup";
    $detectedMessage = "User account added to Administrators group on DeepBlueCLI Rule";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.LogName -eq "Security" -and ($event.id -eq 4728 -or $event.id -eq 4732 -or $event.id -eq 4756) }
            if ($target) {
                foreach ($record in $target) {
                    $eventXML = [xml]$event.ToXml();
                    $groupname = $eventXML.Event.EventData.Data[2]."#text"
                    if ($groupname -eq "Administrators") {
                        $username = $eventXML.Event.EventData.Data[0]."#text"
                        $securityid = $eventXML.Event.EventData.Data[1]."#text"
                        switch ($event.id) {
                            4728 { $result = "User added to global $groupname group" }
                            4732 { $result = "User added to local $groupname group" }
                            4756 { $result = "User added to universal $groupname group" }
                        }
                        $result += "Username: $username`n"
                        $result += "User SID: $securityid`n"   
                        Write-Host
                        Write-Host "Detected! RuleName:$ruleName";
                        Write-Host $detectedMessage;
                        Write-Host $result    
                    }
                }
                    
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}