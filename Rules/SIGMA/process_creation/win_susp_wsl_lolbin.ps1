# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\wsl.exe") -and ($_.message -match "CommandLine.*.* -e .*" -or $_.message -match "CommandLine.*.* --exec .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_wsl_lolbin";
    $detectedMessage = "Detects Possible usage of Windows Subsystem for Linux (WSL) binary as a LOLBIN";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\wsl.exe") -and ($_.message -match "CommandLine.*.* -e .*" -or $_.message -match "CommandLine.*.* --exec .*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
