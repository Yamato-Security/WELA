# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe") -and ($_.message -match "CommandLine.*.*.jse" -or $_.message -match "CommandLine.*.*.vbe" -or $_.message -match "CommandLine.*.*.js" -or $_.message -match "CommandLine.*.*.vba")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_script_execution";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_script_execution";
            $detectedMessage = "Detects suspicious file execution by wscript and cscript";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe") -and ($_.message -match "CommandLine.*.*.jse" -or $_.message -match "CommandLine.*.*.vbe" -or $_.message -match "CommandLine.*.*.js" -or $_.message -match "CommandLine.*.*.vba")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
