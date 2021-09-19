
function Add-Rule {
    $ruleName = "4104-PowerShellScriptBlockCreate";
    $detectedMessage = "detected PowerShell script block created on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 4104 -and $_.ProviderName -eq "Microsoft-Windows-PowerShell/Operational" }

            foreach ($record in $target) {
                $eventXML = [xml] $record.ToXml()
                if (-not ($eventxml.Event.EventData.Data[4]."#text")) {
                    $commandline = $eventXML.Event.EventData.Data[2]."#text"
                    if ($commandline) {
                        $result = Check-Command -EventID 4104
                        Write-Host
                        Write-Host "Detected! RuleName:$ruleName";
                        Write-Host $detectedMessage;
                        Write-host $result
                    }
                }
            }
        };
        . Search-DetectableEvents $args[0]0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}