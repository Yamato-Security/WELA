
function Add-Rule {
    $ruleName = "104-SystemLogClear";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "104-SystemLogClear";
            $detectedMessage = "detected system log cleared on DeepBlueCLI Rule";
            $target = $event | where { $_.ID -eq 104 -and $_.LogName -eq "System" }

            if ($target) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
            }
            foreach ($record in $target) {
                $result = Create-Obj $record $LogFile
                $result.Message = $record.message
                Write-Output $result | Format-Table * -Wrap;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error" -Foreground Yellow;
    }
}