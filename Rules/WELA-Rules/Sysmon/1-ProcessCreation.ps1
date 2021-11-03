
function Add-Rule {
    $ruleName = "1-ProcessCreation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "1-ProcessCreation";
            $detectedMessage = "detected Sysmon process creation on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 1 -and $_.LogName -eq "Microsoft-Windows-Sysmon/Operational" }

            foreach ($record in $target) {
                $eventXML = [xml] $record.ToXml()
                $creator = $eventXML.Event.EventData.Data[14]."#text"
                $commandline = $eventXML.Event.EventData.Data[4]."#text"
                $obj = Create-Obj -event $record
                if ($commandline) {
                    $result = Check-Command -EventID 1 -creator $creator -obj $obj
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;
                    Write-Output $result;
                    Write-Output ""; 
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