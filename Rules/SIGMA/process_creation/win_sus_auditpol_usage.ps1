# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\auditpol.exe" -and ($_.message -match "CommandLine.*.*disable.*" -or $_.message -match "CommandLine.*.*clear.*" -or $_.message -match "CommandLine.*.*remove.*" -or $_.message -match "CommandLine.*.*restore.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_sus_auditpol_usage";
    $detectedMessage = "Threat actors can use auditpol binary to change audit policy configuration to impair detection capability. This can be carried out by selectively disabling/removing certain audit policies as well as restoring a custom policy owned by the threat actor.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\auditpol.exe" -and ($_.message -match "CommandLine.*.*disable.*" -or $_.message -match "CommandLine.*.*clear.*" -or $_.message -match "CommandLine.*.*remove.*" -or $_.message -match "CommandLine.*.*restore.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
