# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\net.exe" -or $_.message -match "Image.*.*\net1.exe") -and $_.message -match "CommandLine.*.* use .*" -and $_.message -match "CommandLine.*.*\.*\.*$.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_net_use_admin_share";
    $detectedMessage = "Detects when an admin share is mounted using net.exe";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\net.exe" -or $_.message -match "Image.*.*\net1.exe") -and $_.message -match "CommandLine.*.* use .*" -and $_.message -match "CommandLine.*.*\.*\.*$.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
