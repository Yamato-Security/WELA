# Get-WinEvent -LogName Security  where {($_.ID -eq "4688" | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    $ruleName = "4688-ProcessCreate";
    $detectedMessage = "detected ProcessCreate on DeepBlueCLI Rule";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $target = $event | where { $_.ID -eq 4668 -and $_.LogName -eq "Security" }

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
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}