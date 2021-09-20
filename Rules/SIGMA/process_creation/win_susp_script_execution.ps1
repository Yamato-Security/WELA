# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe") -and ($_.message -match "CommandLine.*.*.jse.*" -or $_.message -match "CommandLine.*.*.vbe.*" -or $_.message -match "CommandLine.*.*.js.*" -or $_.message -match "CommandLine.*.*.vba.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_script_execution";
    $detectedMessage = "Detects suspicious file execution by wscript and cscript";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe") -and ($_.message -match "CommandLine.*.*.jse.*" -or $_.message -match "CommandLine.*.*.vbe.*" -or $_.message -match "CommandLine.*.*.js.*" -or $_.message -match "CommandLine.*.*.vba.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
