# Get-WinEvent -LogName Security  where {($_.ID -eq "4688" | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    $ruleName = "4688-ProcessCreat";
    $detectedMessage = "detected ProcessCreate on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            if ($event.ProviderName -eq "Security" -and $event.id -eq 4668) {
                $eventXML = [xml]$event.ToXml();
                $commandline = $eventXML.EventData.Data[8]."#text"
                $creator = $eventXML.EventData.Data[8]."#text"

                if ($commandline) {
                    $result = Check-Command -EventID 4688
                    if (!$result) {
                        Write-Host
                        Write-Host "Detected! RuleName:$ruleName";
                        Write-Host $detectedMessage;
                        Write-Host $result
                    }
                }
            }
            
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}