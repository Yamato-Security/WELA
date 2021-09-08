# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\wmic.exe" -and (($_.message -match "CommandLine.*.*process.*" -and $_.message -match "CommandLine.*.*call.*" -and $_.message -match "CommandLine.*.*create .*") -or ($_.message -match "CommandLine.*.* path .*" -and ($_.message -match "CommandLine.*.*AntiVirus.*" -or $_.message -match "CommandLine.*.*Firewall.*") -and $_.message -match "CommandLine.*.*Product.*" -and $_.message -match "CommandLine.*.* get .*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_wmi_execution";
    $detectedMessage = "Detects WMI executing suspicious commands";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\wmic.exe" -and (($_.message -match "CommandLine.*.*process.*" -and $_.message -match "CommandLine.*.*call.*" -and $_.message -match "CommandLine.*.*create .*") -or ($_.message -match "CommandLine.*.* path .*" -and ($_.message -match "CommandLine.*.*AntiVirus.*" -or $_.message -match "CommandLine.*.*Firewall.*") -and $_.message -match "CommandLine.*.*Product.*" -and $_.message -match "CommandLine.*.* get .*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
