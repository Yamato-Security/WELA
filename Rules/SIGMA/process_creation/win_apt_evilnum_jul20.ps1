# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*regsvr32.*" -and $_.message -match "CommandLine.*.*/s.*" -and $_.message -match "CommandLine.*.*/i.*" -and $_.message -match "CommandLine.*.*\AppData\Roaming\.*" -and $_.message -match "CommandLine.*.*.ocx.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_evilnum_jul20";
    $detectedMessage = "Detects Golden Chickens deployment method as used by Evilnum in report published in July 2020";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*regsvr32.*" -and $_.message -match "CommandLine.*.*/s.*" -and $_.message -match "CommandLine.*.*/i.*" -and $_.message -match "CommandLine.*.*\AppData\Roaming\.*" -and $_.message -match "CommandLine.*.*.ocx.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
