
function Add-Rule {
    $ruleName = "1-ProcessCreation";
    $detectedMessage = "detected Sysmon process creation on DeepBlueCLI Rule";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 1 -and $_.ProviderName -eq "Microsoft-Windows-Sysmon/Operational" }

            foreach ($record in $target) {
                $eventXML = [xml] $record.ToXml()
                $creator = $eventXML.Event.EventData.Data[14]."#text"
                $commandline = $eventXML.Event.EventData.Data[4]."#text"
                if ($commandline) {
                    $result = Check-Command -EventID 1 -creator $creator
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;
                    Write-host $result
                }
            }
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}