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
            $target = $event | where { $_.ID -eq 4688 -and $_.LogName -eq "Security" }

            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml();
                $commandline = $eventXML.Event.EventData.Data[8]."#text"
                $creator = $eventXML.Event.EventData.Data[13]."#text"
                        
                if ($commandline) {
                    $obj = Create-Obj -event $record $LogFile
                    $result = Check-Command -EventID 4688 $commandline $creator -obj $obj
                    if ($result) {
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