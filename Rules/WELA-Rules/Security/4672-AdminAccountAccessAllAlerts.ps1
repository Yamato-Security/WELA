
function Add-Rule {
    $ruleName = "4672-AdminAccountAccessAllAlerts";
    $detectedMessage = "Logon with SeDebugPrivilege (admin access)`nSpecial privileges assgned to new logons on DeepBlueCLI Rule";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 4672 -and $_.ProviderName -eq "Security" -and $_.message -Match "SeDebugPrivilege" }

            $multipleadminlogons = @{}
            $adminlogons = @{}
            if ($target) {
                foreach ($record in $target) {
                    $eventXML = [xml]$record.ToXml();
                    $username = $eventXML.Event.EventData.Data[1]."#text"
                    $domain = $eventXML.Event.EventData.Data[2]."#text"
                    $securityid = $eventXML.Event.EventData.Data[3]."#text"
                    $privileges = $eventXML.Event.EventData.Data[4]."#text"
                    if ($adminlogons.ContainsKey($username) -and !($adminlogons.$username -Match $securityid)) {
                        multipleadminlogons.Set_Item($username, 1)
                        adminlogons.Set_Item($username, $adminlogons.$username)
                    }
                    else {
                        $adminlogons.add($username, $securityid)
                    }                   
                }
                foreach ($usernameKey in $adminlogons.Keys) {
                    if ($multipleadminlogons.$usernameKey) {
                        $result = "Multiple admin logons for one account"
                        $result += "Username: $username`n"
                        $result += "User SID Access Count: " + $securityid.split().Count
                        Write-Host "Detected! RuleName:$ruleName";
                        Write-Host $detectedMessage;
                        Write-Host $result
                    }
                }
            }
        }
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}