# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\WindowsSensor.exe.*" -and $_.message -match "CommandLine.*.* /uninstall.*" -and $_.message -match "CommandLine.*.* /quiet.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_uninstall_crowdstrike_falcon";
    $detectedMessage = "Adversaries may disable security tools to avoid possible detection of their tools and activities by uninstalling Crowdstrike Falcon";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\WindowsSensor.exe.*" -and $_.message -match "CommandLine.*.* /uninstall.*" -and $_.message -match "CommandLine.*.* /quiet.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
