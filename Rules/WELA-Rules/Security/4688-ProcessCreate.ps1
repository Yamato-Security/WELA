# Get-WinEvent -LogName Security  where {($_.ID -eq "4688" | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    $ruleName = "4688-ProcessCreat";
    $detectedMessage = "detected ProcessCreate on DeepBlueCLI Rule";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 4668 -and $event.ProviderName -eq "Security" }

            if ($target) {
                foreach ($record in $target) {
                    $eventXML = [xml]$record.ToXml();
                    $commandline = $eventXML.EventData.Data[8]."#text"
                    $creator = $eventXML.EventData.Data[13]."#text"

                    if ($commandline) {
                        $result = Check-Command -EventID 4688 $commandline $creator
                        if ($result) {
                            Write-Host
                            Write-Host "Detected! RuleName:$ruleName";
                            Write-Host $detectedMessage;
                            Write-Host $result
                        }
                    }
                }
            }
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}