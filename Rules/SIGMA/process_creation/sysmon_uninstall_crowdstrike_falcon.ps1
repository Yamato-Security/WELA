# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\WindowsSensor.exe" -and $_.message -match "CommandLine.*.* /uninstall" -and $_.message -match "CommandLine.*.* /quiet") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_uninstall_crowdstrike_falcon";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_uninstall_crowdstrike_falcon";
            $detectedMessage = "Adversaries may disable security tools to avoid possible detection of their tools and activities by uninstalling Crowdstrike Falcon";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\\WindowsSensor.exe" -and $_.message -match "CommandLine.*.* /uninstall" -and $_.message -match "CommandLine.*.* /quiet") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
