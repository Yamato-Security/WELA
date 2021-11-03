
function Add-Rule {
    $ruleName = "4728_4732_4756-AddedUserAdministratorsGroup";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "4728_4732_4756-AddedUserAdministratorsGroup";
            $detectedMessage = "User account added to Administrators group on DeepBlueCLI Rule";
            $target = $event | where { $_.LogName -eq "Security" -and ($_.id -eq 4728 -or $_.id -eq 4732 -or $_.id -eq 4756) }
            if ($target) {
                foreach ($record in $target) {
                    $eventXML = [xml]$record.ToXml();
                    $groupname = $eventXML.Event.EventData.Data[2]."#text"
                    if ($groupname -eq "Administrators") {
                        $result = Create-Obj $record $LogFile
                        $username = $eventXML.Event.EventData.Data[0]."#text"
                        $securityid = $eventXML.Event.EventData.Data[1]."#text"
                        $result.Message = $detectedMessage
                        switch ($record.id) {
                            4728 { $result.Results = "User added to global $groupname group`n" }
                            4732 { $result.Results = "User added to local $groupname group`n" }
                            4756 { $result.Results = "User added to universal $groupname group`n" }
                        }
                        $result.Results += "Username: $username`n"
                        $result.Results += "User SID: $securityid`n"   
                        Write-Output "";
                        Write-Output "Detected! RuleName:$ruleName";
                        Write-Output $detectedMessage;
                        Write-Output $result;
                        Write-Output "";
                    }
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