# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\wmic.exe" -and (($_.message -match "CommandLine.*.*process" -and $_.message -match "CommandLine.*.*call" -and $_.message -match "CommandLine.*.*create ") -or ($_.message -match "CommandLine.*.* path " -and ($_.message -match "CommandLine.*.*AntiVirus" -or $_.message -match "CommandLine.*.*Firewall") -and $_.message -match "CommandLine.*.*Product" -and $_.message -match "CommandLine.*.* get "))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_wmi_execution";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_wmi_execution";
            $detectedMessage = "Detects WMI executing suspicious commands";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\wmic.exe" -and (($_.message -match "CommandLine.*.*process" -and $_.message -match "CommandLine.*.*call" -and $_.message -match "CommandLine.*.*create ") -or ($_.message -match "CommandLine.*.* path " -and ($_.message -match "CommandLine.*.*AntiVirus" -or $_.message -match "CommandLine.*.*Firewall") -and $_.message -match "CommandLine.*.*Product" -and $_.message -match "CommandLine.*.* get "))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
