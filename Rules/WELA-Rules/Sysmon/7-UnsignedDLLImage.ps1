
function Add-Rule {
    $ruleName = "7-UnsignedDLLImage";
    # This can be very chatty, so Recommend disabled.
    $detectedMessage = "detected Sysmon Unsigned Image(DLL) on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 7 -and $_.ProviderName -eq "Microsoft-Windows-Sysmon/Operational" }

            foreach ($record in $target) {
                $eventXML = [xml] $record.ToXml()
                if ($eventXML.Event.EventData.Data[6]."#text" -eq "false") {
                    $image = $eventXML.Event.EventData.Data[3]."#text"
                    $result = "Loaded by: $image"
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;
                    Write-Output $result
                }
            }
        };
        . Search-DetectableEvents $args[0]0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}