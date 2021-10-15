
function Add-Rule {
    $ruleName = "4103-PowerShellExecute";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $ruleName = "4103-PowerShellExecute";
            $detectedMessage = "detected PowerShell execute on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 4103 -and $_.LogName -eq "Microsoft-Windows-PowerShell/Operational" }

            foreach ($record in $target) {
                $eventXML = [xml] $record.ToXml()
                $commandline = $eventXML.Event.EventData.Data[2]."#text"
                if ($commandline -Match "Host Application") { 
                    # Multiline replace, remove everything before "Host Application = "
                    $commandline = $commandline -Replace "(?ms)^.*Host.Application = ", ""
                    # Remove every line after the "Host Application = " line.
                    $commandline = $commandline -Replace "(?ms)`n.*$", ""
                    if ($commandline) {
                        $obj = Create-Obj -event $record $LogFile
                        $result = Check-Command -EventID 4103 -commandline $commandline -obj $obj
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