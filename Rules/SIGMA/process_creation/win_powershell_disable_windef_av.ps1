# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\powershell.exe" -and ($_.message -match "CommandLine.*.*-DisableBehaviorMonitoring $true" -or $_.message -match "CommandLine.*.*-DisableRuntimeMonitoring $true")) -or ($_.message -match "CommandLine.*.*sc" -and $_.message -match "CommandLine.*.*stop" -and $_.message -match "CommandLine.*.*WinDefend") -or ($_.message -match "CommandLine.*.*sc" -and $_.message -match "CommandLine.*.*config" -and $_.message -match "CommandLine.*.*WinDefend" -and $_.message -match "CommandLine.*.*start=disabled"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_powershell_disable_windef_av";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_powershell_disable_windef_av";
            $detectedMessage = "Detects attackers attempting to disable Windows Defender using Powershell";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\powershell.exe" -and ($_.message -match "CommandLine.*.*-DisableBehaviorMonitoring $true" -or $_.message -match "CommandLine.*.*-DisableRuntimeMonitoring $true")) -or ($_.message -match "CommandLine.*.*sc" -and $_.message -match "CommandLine.*.*stop" -and $_.message -match "CommandLine.*.*WinDefend") -or ($_.message -match "CommandLine.*.*sc" -and $_.message -match "CommandLine.*.*config" -and $_.message -match "CommandLine.*.*WinDefend" -and $_.message -match "CommandLine.*.*start=disabled"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
