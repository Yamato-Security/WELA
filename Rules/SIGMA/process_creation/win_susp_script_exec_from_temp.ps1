# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\mshta.exe" -or $_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe") -and ($_.message -match "CommandLine.*.*\\Windows\\Temp.*" -or $_.message -match "CommandLine.*.*\\Temporary Internet.*" -or $_.message -match "CommandLine.*.*\\AppData\\Local\\Temp.*" -or $_.message -match "CommandLine.*.*\\AppData\\Roaming\\Temp.*" -or $_.message -match "CommandLine.*.*%TEMP%.*" -or $_.message -match "CommandLine.*.*%TMP%.*" -or $_.message -match "CommandLine.*.*%LocalAppData%\\Temp.*")) -and  -not ($_.message -match "CommandLine.*.* >.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_script_exec_from_temp";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_script_exec_from_temp";
            $detectedMessage = "Detects a suspicious script executions from temporary folder";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\mshta.exe" -or $_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe") -and ($_.message -match "CommandLine.*.*\\Windows\\Temp.*" -or $_.message -match "CommandLine.*.*\\Temporary Internet.*" -or $_.message -match "CommandLine.*.*\\AppData\\Local\\Temp.*" -or $_.message -match "CommandLine.*.*\\AppData\\Roaming\\Temp.*" -or $_.message -match "CommandLine.*.*%TEMP%.*" -or $_.message -match "CommandLine.*.*%TMP%.*" -or $_.message -match "CommandLine.*.*%LocalAppData%\\Temp.*")) -and -not ($_.message -match "CommandLine.*.* >.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
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
