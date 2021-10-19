
function Add-Rule {
    $ruleName = "4104-PowerShellScriptBlockCreate";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $ruleName = "4104-PowerShellScriptBlockCreate";
            $detectedMessage = "detected PowerShell script block created on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 4104 -and $_.LogName -eq "Microsoft-Windows-PowerShell/Operational" }
            foreach ($record in $target) {
                $eventXML = [xml] $record.ToXml()
                
                if (-not ($eventxml.Event.EventData.Data[4]."#text")) {
                    $commandline = $eventXML.Event.EventData.Data[2]."#text"
                    if ($commandline) {
                        $obj = Create-Obj -event $record 
                        $result = Check-Command -EventID 4104 -commandline $commandline -obj $obj
                        if ($result) {
                            Write-Output ""; 
                            Write-Output "Detected! RuleName:$ruleName"
                            Write-Output $detectedMessage
                            Write-Output $result    
                        }
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