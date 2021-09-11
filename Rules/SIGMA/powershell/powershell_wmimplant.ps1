# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match "ScriptBlockText.*.*WMImplant.*" -or $_.message -match "ScriptBlockText.*.* change_user .*" -or $_.message -match "ScriptBlockText.*.* gen_cli .*" -or $_.message -match "ScriptBlockText.*.* command_exec .*" -or $_.message -match "ScriptBlockText.*.* disable_wdigest .*" -or $_.message -match "ScriptBlockText.*.* disable_winrm .*" -or $_.message -match "ScriptBlockText.*.* enable_wdigest .*" -or $_.message -match "ScriptBlockText.*.* enable_winrm .*" -or $_.message -match "ScriptBlockText.*.* registry_mod .*" -or $_.message -match "ScriptBlockText.*.* remote_posh .*" -or $_.message -match "ScriptBlockText.*.* sched_job .*" -or $_.message -match "ScriptBlockText.*.* service_mod .*" -or $_.message -match "ScriptBlockText.*.* process_kill .*" -or $_.message -match "ScriptBlockText.*.* active_users .*" -or $_.message -match "ScriptBlockText.*.* basic_info .*" -or $_.message -match "ScriptBlockText.*.* power_off .*" -or $_.message -match "ScriptBlockText.*.* vacant_system .*" -or $_.message -match "ScriptBlockText.*.* logon_events .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "powershell_wmimplant";
    $detectedMessage = "Detects parameters used by WMImplant";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.message -match "ScriptBlockText.*.*WMImplant.*" -or $_.message -match "ScriptBlockText.*.* change_user .*" -or $_.message -match "ScriptBlockText.*.* gen_cli .*" -or $_.message -match "ScriptBlockText.*.* command_exec .*" -or $_.message -match "ScriptBlockText.*.* disable_wdigest .*" -or $_.message -match "ScriptBlockText.*.* disable_winrm .*" -or $_.message -match "ScriptBlockText.*.* enable_wdigest .*" -or $_.message -match "ScriptBlockText.*.* enable_winrm .*" -or $_.message -match "ScriptBlockText.*.* registry_mod .*" -or $_.message -match "ScriptBlockText.*.* remote_posh .*" -or $_.message -match "ScriptBlockText.*.* sched_job .*" -or $_.message -match "ScriptBlockText.*.* service_mod .*" -or $_.message -match "ScriptBlockText.*.* process_kill .*" -or $_.message -match "ScriptBlockText.*.* active_users .*" -or $_.message -match "ScriptBlockText.*.* basic_info .*" -or $_.message -match "ScriptBlockText.*.* power_off .*" -or $_.message -match "ScriptBlockText.*.* vacant_system .*" -or $_.message -match "ScriptBlockText.*.* logon_events .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
