# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\winlogon.exe" -or $_.message -match "ParentImage.*.*\services.exe" -or $_.message -match "ParentImage.*.*\lsass.exe" -or $_.message -match "ParentImage.*.*\csrss.exe" -or $_.message -match "ParentImage.*.*\smss.exe" -or $_.message -match "ParentImage.*.*\wininit.exe" -or $_.message -match "ParentImage.*.*\spoolsv.exe" -or $_.message -match "ParentImage.*.*\searchindexer.exe") -and ($_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\cmd.exe") -and $_.message -match "User.*NT AUTHORITY\SYSTEM") -and  -not ($_.message -match "CommandLine.*.* route .*" -and $_.message -match "CommandLine.*.* ADD .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_abusing_debug_privilege";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_abusing_debug_privilege";
            $detectedMessage = "Detection of unusual child processes by different system processes";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\winlogon.exe" -or $_.message -match "ParentImage.*.*\\services.exe" -or $_.message -match "ParentImage.*.*\\lsass.exe" -or $_.message -match "ParentImage.*.*\\csrss.exe" -or $_.message -match "ParentImage.*.*\\smss.exe" -or $_.message -match "ParentImage.*.*\\wininit.exe" -or $_.message -match "ParentImage.*.*\\spoolsv.exe" -or $_.message -match "ParentImage.*.*\\searchindexer.exe") -and ($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\cmd.exe") -and $_.message -match "User.*NT AUTHORITY\\SYSTEM") -and -not ($_.message -match "CommandLine.*.* route .*" -and $_.message -match "CommandLine.*.* ADD .*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
