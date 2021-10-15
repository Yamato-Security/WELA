
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
                    $result = Create-Obj $record $LogFile
                    $eventXML = [xml]$record.ToXml();
                    $username = $eventXML.Event.EventData.Data[0]."#text"
                    $securityid = $eventXML.Event.EventData.Data[2]."#text"
                    $result.Message = $detectedMessage
                    $result.Results = "New User Created"
                    $result.Results += "Username: $username`n"
                    $result.Results += "User SID: $securityid`n"
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