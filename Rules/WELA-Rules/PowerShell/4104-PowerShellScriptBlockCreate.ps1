
function Add-Rule {
    $ruleName = "4104-PowerShellScriptBlockCreate";
    $detectedMessage = "detected PowerShell script block created on DeepBlueCLI Rule";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 4104 -and $_.LogName -eq "Microsoft-Windows-PowerShell" }

            foreach ($record in $target) {
                $eventXML = [xml] $record.ToXml()
                if (-not ($eventxml.Event.EventData.Data[4]."#text")) {
                    $commandline = $eventXML.Event.EventData.Data[2]."#text"
                    if ($commandline) {
                        $obj = Create-Obj -event $record 
                        $result = Check-Command -EventID 4104 -commandline $commandline -obj $obj
                        Write-Host
                        Write-Host "Detected! RuleName:$ruleName";
                        Write-Host $detectedMessage;
                        Write-output $result
                    }
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}