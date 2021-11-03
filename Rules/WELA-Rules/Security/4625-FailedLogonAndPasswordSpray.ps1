
function Add-Rule {
    $ruleName = "4625_FailedLogonAndPasswordSpray";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $maxfailedlogons = 5
            $ruleName = "4625_FailedLogonAndPasswordSpray";
            $detectedMessage = "High number of logon failures for one /multi account on DeepBlueCLI Rule";

            $target = $event | where { $_.LogName -eq "Security" -and $_.id -eq 4625 }
            if ($target) {
                $totalfailedaccounts = 0;
                $failedlogons = @{}
                $failedLogonTriedTimeRecord = @{}
                foreach ($record in $target) {
                    $eventXML = [xml]$record.ToXml();
                    $username = $eventXML.Event.EventData.Data[5]."#text"
                    if ($failedlogons.ContainsKey($username)) {
                        $failedlogons[$username] += 1;
                    }
                    else {
                        $failedlogons[$username] = 1
                        $totalfailedaccounts += 1
                    }
                    $totalfailedlogons += 1
                    $failedLogonTriedTimeRecord[$username] = $record
                }
                $detectcount = 0
                foreach ($username in $failedlogons.Keys) {
                    if ($failedlogons[$username] -gt $maxfailedlogons) {
                        if ($detectcount -eq 0) {
                            Write-Output ""; 
                            Write-Output "Detected! RuleName:$ruleName";
                            Write-Output $detectedMessage;
                        }
                        $cnt = $failedlogons[$username]
                        $result = Create-Obj $failedLogonTriedTimeRecord[$username] $LogFile
                        $result.Message = $detectedMessage
                        $result.Results = "Username: $username`n"
                        $result.Results += "Total logon failures: $cnt"
                        Write-Output $result;
                        Write-Output "";
                    }
                    $detectcount += 1
                }
                # Password spraying:
                if (($target.Count -gt $maxfailedlogons) -and ($target.Count -gt 1)) {
                    $result = Create-Obj -logname $LogFile;
                    $result.Message = $detectedMessage
                    $result.EventID = 4625
                    $result.Results = "Total accounts: $totalfailedaccounts`n"
                    $result.Results += "Total logon failures: $totalfailedlogons`n"

                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;
                    Write-Output $result;
                    Write-Output ""; 
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