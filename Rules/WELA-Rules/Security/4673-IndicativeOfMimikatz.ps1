
function Add-Rule {
    $ruleName = "4673_IndicativeOfMimikatz";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "4673_IndicativeOfMimikatz";
            $detectedMessage = "Potentially indicative of Mimikatz, multiple sensitive privilege calls have been made on DeepBlueCLI Rule()";        
            $target = $event | where { $_.LogName -eq "Security" -and ($_.id -eq 4673) }
            $maxtotalsensprivuse = 4
            $resultoutput = @{}
            $cnt = 1;
            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml();
                $username = $eventXML.Event.EventData.Data[1]."#text"
                $domainname = $eventXML.Event.EventData.Data[2]."#text"
                $key = "$username\\$domainname"
                $result = Create-Obj $record $LogFile
                $result.Results = "Username: $username`nDomain Name:$domainname`n"
                if (!$resultoutput.ContainsKey($key)) {
                    $resultoutput.Add($key, $result)
                }
                # Newest sort in DeepBlueCLI. but Oldest Sort in WELA for log
                if ($target.Count - $cnt + 1 -eq $maxtotalsensprivuse) {
                    $result.Message = "Sensititive Privilege Use Exceeds Threshold"
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;
                    Write-Output $result;
                    Write-Output "";
                    break;
                }
                $cnt += 1;
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