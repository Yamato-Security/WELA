# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\mshta.exe" -and ($_.message -match "CommandLine.*.*vbscript.*" -or $_.message -match "CommandLine.*.*.jpg.*" -or $_.message -match "CommandLine.*.*.png.*" -or $_.message -match "CommandLine.*.*.lnk.*" -or $_.message -match "CommandLine.*.*.xls.*" -or $_.message -match "CommandLine.*.*.doc.*" -or $_.message -match "CommandLine.*.*.zip.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_mshta_execution";
    $detectedMessage = "Detection for mshta.exe suspicious execution patterns sometimes involving file polyglotism";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\mshta.exe" -and ($_.message -match "CommandLine.*.*vbscript.*" -or $_.message -match "CommandLine.*.*.jpg.*" -or $_.message -match "CommandLine.*.*.png.*" -or $_.message -match "CommandLine.*.*.lnk.*" -or $_.message -match "CommandLine.*.*.xls.*" -or $_.message -match "CommandLine.*.*.doc.*" -or $_.message -match "CommandLine.*.*.zip.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
