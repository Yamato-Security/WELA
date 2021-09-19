# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*-Sta.*" -and $_.message -match "CommandLine.*.*-Nop.*" -and $_.message -match "CommandLine.*.*-Window.*" -and $_.message -match "CommandLine.*.*Hidden.*" -and ($_.message -match "CommandLine.*.*-Command.*" -or $_.message -match "CommandLine.*.*-EncodedCommand.*")) -or ($_.message -match "CommandLine.*.*sv o (New-Object IO.MemorySteam);sv d .*" -or $_.message -match "CommandLine.*.*mshta file.hta.*" -or $_.message -match "CommandLine.*.*GruntHTTP.*" -or $_.message -match "CommandLine.*.*-EncodedCommand cwB2ACAAbwAgA.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_covenant";
    $detectedMessage = "Detects suspicious command lines used in Covenant luanchers";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*-Sta.*" -and $_.message -match "CommandLine.*.*-Nop.*" -and $_.message -match "CommandLine.*.*-Window.*" -and $_.message -match "CommandLine.*.*Hidden.*" -and ($_.message -match "CommandLine.*.*-Command.*" -or $_.message -match "CommandLine.*.*-EncodedCommand.*")) -or ($_.message -match "CommandLine.*.*sv o (New-Object IO.MemorySteam);sv d .*" -or $_.message -match "CommandLine.*.*mshta file.hta.*" -or $_.message -match "CommandLine.*.*GruntHTTP.*" -or $_.message -match "CommandLine.*.*-EncodedCommand cwB2ACAAbwAgA.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
