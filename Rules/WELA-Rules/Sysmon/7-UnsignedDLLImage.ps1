
function Add-Rule {
    $ruleName = "7-UnsignedDLLImage";
    # This can be very chatty, so Recommend disabled.
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "7-UnsignedDLLImage";
            $detectedMessage = "detected Sysmon Unsigned Image(DLL) on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 7 -and $_.LogName -eq "Microsoft-Windows-Sysmon/Operational" }

            foreach ($record in $target) {
                $eventXML = [xml] $record.ToXml()
                if ($eventXML.Event.EventData.Data[6]."#text" -eq "false") {
                    $image = $eventXML.Event.EventData.Data[3]."#text"
                    $result = Create-Obj $record $LogFile
                    $result.Message = $detectedMessage
                    $result.Results = "Loaded by: $image"
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;
                    Write-Output $result
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