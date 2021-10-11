# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\powershell.exe") -and $_.message -match "ParentImage.*.*\Windows\Installer\.*" -and $_.message -match "ParentImage.*.*msi.*" -and ($_.message -match "ParentImage.*.*tmp")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_always_install_elevated_msi_spawned_cmd_and_powershell";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_always_install_elevated_msi_spawned_cmd_and_powershell";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\powershell.exe") -and $_.message -match "ParentImage.*.*\\Windows\\Installer\\.*" -and $_.message -match "ParentImage.*.*msi.*" -and ($_.message -match "ParentImage.*.*tmp")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
