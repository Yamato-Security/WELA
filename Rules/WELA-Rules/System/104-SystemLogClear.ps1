
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
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
            }
            foreach ($record in $target) {
                $result = Create-Obj $record $LogFile
                $result.Message = $record.message
                Write-Output $result;
                Write-Output ""; 
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