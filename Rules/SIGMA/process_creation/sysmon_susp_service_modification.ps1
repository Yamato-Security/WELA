# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*Stop-Service .*" -or $_.message -match "CommandLine.*.*Remove-Service .*") -and ($_.message -match "CommandLine.*.* McAfeeDLPAgentService.*" -or $_.message -match "CommandLine.*.* Trend Micro Deep Security Manager.*" -or $_.message -match "CommandLine.*.* TMBMServer.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_service_modification";
    $detectedMessage = "Adversaries may disable security tools to avoid possible detection of their tools and activities by stopping antivirus service";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*Stop-Service .*" -or $_.message -match "CommandLine.*.*Remove-Service .*") -and ($_.message -match "CommandLine.*.* McAfeeDLPAgentService.*" -or $_.message -match "CommandLine.*.* Trend Micro Deep Security Manager.*" -or $_.message -match "CommandLine.*.* TMBMServer.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
