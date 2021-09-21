# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\dxcap.exe" -and $_.message -match "CommandLine.*.*-c.*" -and $_.message -match "CommandLine.*.*.exe.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_dxcap";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_dxcap";
            $detectedMessage = "Detects execution of of Dxcap.exe";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\dxcap.exe" -and $_.message -match "CommandLine.*.*-c.*" -and $_.message -match "CommandLine.*.*.exe.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
