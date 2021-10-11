
function Add-Rule {
    $ruleName = "8003-ApplockerWarning";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $ruleName = "8003-ApplockerWarning";
            $detectedMessage = "detected Applocker warning on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 8003 -and $_.LogName -eq "Microsoft-Windows-AppLocker/EXE and DLL" }

            if ($target) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
            }
            foreach ($record in $target) {
                $result = Create-Obj $record $LogFile
                $result.Message = $detectedMessage
                $command = $event.message -Replace " was .*$", ""
                $result.Command = $command
                $result.Results = $record.message
                Write-Output $result | Format-Table * -Wrap;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}