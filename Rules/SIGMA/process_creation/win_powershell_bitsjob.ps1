# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*Start-BitsTransfer.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_powershell_bitsjob";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_powershell_bitsjob";
                    $detectedMessage = "Detect download by BITS jobs via PowerShell";
                $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*Start-BitsTransfer.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
