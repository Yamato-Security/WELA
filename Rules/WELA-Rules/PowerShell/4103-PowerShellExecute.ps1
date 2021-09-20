
function Add-Rule {
    $ruleName = "4103-PowerShellExecute";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $ruleName = "4103-PowerShellExecute";
            $detectedMessage = "detected PowerShell execute on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 4103 -and $_.LogName -eq "Microsoft-Windows-PowerShell" }

            foreach ($record in $target) {
                $eventXML = [xml] $record.ToXml()
                $commandline = $eventXML.Event.EventData.Data[2]."#text"
                if ($commandline -Match "Host Application") { 
                    # Multiline replace, remove everything before "Host Application = "
                    $commandline = $commandline -Replace "(?ms)^.*Host.Application = ", ""
                    # Remove every line after the "Host Application = " line.
                    $commandline = $commandline -Replace "(?ms)`n.*$", ""
                    if ($commandline) {
                        $obj = Create-Obj -event $record                            
                        $result = Check-Command -EventID 4103 -commandline $commandline -obj $obj
                        Write-Host
                        Write-Host "Detected! RuleName:$ruleName";
                        Write-Host $detectedMessage;
                        Write-host $result.Result
                    }
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}