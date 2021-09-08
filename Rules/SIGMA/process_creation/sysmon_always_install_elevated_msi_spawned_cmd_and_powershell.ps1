# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\powershell.exe") -and $_.message -match "ParentImage.*.*\Windows\Installer\.*" -and $_.message -match "ParentImage.*.*msi.*" -and ($_.message -match "ParentImage.*.*tmp")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_always_install_elevated_msi_spawned_cmd_and_powershell";
    $detectedMessage = "This rule will looks for Windows Installer service (msiexec.exe) spawned command line and/or powershell";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\powershell.exe") -and $_.message -match "ParentImage.*.*\Windows\Installer\.*" -and $_.message -match "ParentImage.*.*msi.*" -and ($_.message -match "ParentImage.*.*tmp")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
