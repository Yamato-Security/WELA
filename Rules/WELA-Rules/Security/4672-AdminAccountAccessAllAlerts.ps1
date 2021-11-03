
function Add-Rule {
    $ruleName = "4672-AdminAccountAccessAllAlerts";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $ruleName = "4672-AdminAccountAccessAllAlerts";
            $detectedMessage = "Logon with SeDebugPrivilege (admin access)`nSpecial privileges assgned to new logons on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 4672 -and $_.LogName -eq "Security" }
            $RecentLogonTimeRecord = @{}
            $multipleadminlogons = @{}
            $adminlogons = @{}
            if ($target) {
                foreach ($record in $target) {
                    $eventXML = [xml]$record.ToXml();
                    $username = $eventXML.Event.EventData.Data[1]."#text"
                    $domain = $eventXML.Event.EventData.Data[2]."#text"
                    $securityid = $eventXML.Event.EventData.Data[3]."#text"
                    $privileges = $eventXML.Event.EventData.Data[4]."#text"
                    if ($adminlogons.ContainsKey($username)) {
                        $string = $adminlogons.$username
                        if (!($string -Match $securityid)) {
                            $multipleadminlogons.Set_Item($username, 1)
                            $string += " $securityid"
                            $adminlogons.Set_Item($username, $string)
                        }
                    }
                    else {
                        $adminlogons.add($username, $securityid)
                    }
                    #  evtx file  read is Oldest in WELA. but Latest in DeepBlueCLI
                    if (! $RecentLogonTimeRecord.containsKey($username)) {
                        $RecentLogonTimeRecord[$username] = $record
                    }
                }
                foreach ($usernameKey in $adminlogons.Keys) {
                    $securityid = $adminlogons.Get_Item($usernameKey)
                    if ($multipleadminlogons.$usernameKey) {
                        $result = Create-Obj $RecentLogonTimeRecord[$usernameKey] $LogFile
                        $result.Message = $detectedMessage
                        $result.Results = "Multiple admin logons for one account"
                        $result.Results += "Username: $usernameKey`n"
                        $result.Results += "User SID Access Count: " + $securityid.split().Count
                        Write-Output "Detected! RuleName:$ruleName";
                        Write-Output $detectedMessage;
                        Write-Output $result;
                        Write-Output ""; 
                    }
                }
            }
        }
        . Search-DetectableEvents $args;
    };
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}