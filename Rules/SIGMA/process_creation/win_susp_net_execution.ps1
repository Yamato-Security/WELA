# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\net.exe" -or $_.message -match "Image.*.*\net1.exe") -and ($_.message -match "CommandLine.*.* group.*" -or $_.message -match "CommandLine.*.* localgroup.*" -or $_.message -match "CommandLine.*.* user.*" -or $_.message -match "CommandLine.*.* view.*" -or $_.message -match "CommandLine.*.* share.*" -or $_.message -match "CommandLine.*.* accounts.*" -or $_.message -match "CommandLine.*.* stop .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_net_execution";
    $detectedMessage = "Detects execution of Net.exe, whether suspicious or benign.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\net.exe" -or $_.message -match "Image.*.*\net1.exe") -and ($_.message -match "CommandLine.*.* group.*" -or $_.message -match "CommandLine.*.* localgroup.*" -or $_.message -match "CommandLine.*.* user.*" -or $_.message -match "CommandLine.*.* view.*" -or $_.message -match "CommandLine.*.* share.*" -or $_.message -match "CommandLine.*.* accounts.*" -or $_.message -match "CommandLine.*.* stop .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
