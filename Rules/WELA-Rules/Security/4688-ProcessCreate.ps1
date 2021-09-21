# Get-WinEvent -LogName Security  where {($_.ID -eq "4688" | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    $ruleName = "4688-ProcessCreate";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $ruleName = "4688-ProcessCreate";
            $detectedMessage = "detected ProcessCreate on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 4668 -and $_.LogName -eq "Security" }

            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml();
                $commandline = $eventXML.EventData.Data[8]."#text"
                $creator = $eventXML.EventData.Data[13]."#text"
                $obj = Create-Obj -event $record                            
                        
                if ($commandline) {
                    $result = Check-Command -EventID 4688 $commandline $creator -obj $obj
                    if ($result) {
                        Write-Host
                        Write-Host "Detected! RuleName:$ruleName";
                        Write-Host $detectedMessage;
                        Write-Host $result;
Write-Host
                    }
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}