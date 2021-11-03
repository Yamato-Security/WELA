# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*reg" -and $_.message -match "CommandLine.*.* add " -and $_.message -match "CommandLine.*.*\\Services\\VSS\\Diag" -and $_.message -match "CommandLine.*.*/d Disabled") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_volsnap_disable";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_volsnap_disable";
            $detectedMessage = "Detects commands that temporarily turn off Volume Snapshots";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*reg" -and $_.message -match "CommandLine.*.* add " -and $_.message -match "CommandLine.*.*\\Services\\VSS\\Diag" -and $_.message -match "CommandLine.*.*/d Disabled") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
