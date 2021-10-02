
function Add-Rule {
    $ruleName = "7045-ServiceCreated";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "7045-ServiceCreated";
            $detectedMessage = "detected Service Create on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 7045 -and $_.LogName -eq "System" }

            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml();
                # A service was installed in the system.
                $servicename = $eventXML.Event.EventData.Data[0]."#text"
                $commandline = $eventXML.Event.EventData.Data[1]."#text"
                # Check for suspicious service name
                $text = (Check-Regex $servicename 1)
                if ($text) {
                    $result = Create-Obj $record $LogFile
                    $result.Command = $commandline
                    $result.Results = "Service name: $servicename`n"
                    $result.Results += $text 
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;
                    Write-Output $result | Format-Table * -Wrap;
                    Write-Host
                }
                # Check for suspicious cmd
                if ($commandline) {
                    $servicecmd = 1 # CLIs via service creation get extra checks 
                    $ruleName = "7045-ServiceCreated";
                    $detectedMessage = "detected Service Create on DeepBlueCLI Rule";
                    $obj = Create-Obj -event $record                            
                    $result = Check-Command -EventID 7045 -servicecmd $servicecmd -obj $obj
                    if ($result) {
                        Write-Host
                        Write-Host "Detected! RuleName:$ruleName";
                        Write-Host $detectedMessage;
                        Write-Output $result | Format-Table * -Wrap;
                        Write-Host
                    }
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}