# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*Stop-Service " -or $_.message -match "CommandLine.*.*Remove-Service ") -and ($_.message -match "CommandLine.*.* McAfeeDLPAgentService" -or $_.message -match "CommandLine.*.* Trend Micro Deep Security Manager" -or $_.message -match "CommandLine.*.* TMBMServer")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_service_modification";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_service_modification";
            $detectedMessage = "Adversaries may disable security tools to avoid possible detection of their tools and activities by stopping antivirus service";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*Stop-Service " -or $_.message -match "CommandLine.*.*Remove-Service ") -and ($_.message -match "CommandLine.*.* McAfeeDLPAgentService" -or $_.message -match "CommandLine.*.* Trend Micro Deep Security Manager" -or $_.message -match "CommandLine.*.* TMBMServer")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
