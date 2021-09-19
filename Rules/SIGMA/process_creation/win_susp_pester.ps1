# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\powershell.exe" -and $_.message -match "CommandLine.*.*Pester.*" -and $_.message -match "CommandLine.*.*Get-Help.*") -or ($_.ID -eq "1" -and $_.message -match "Image.*.*\cmd.exe" -and $_.message -match "CommandLine.*.*pester.*" -and $_.message -match "CommandLine.*.*;.*" -and ($_.message -match "CommandLine.*.*help.*" -or $_.message -match "CommandLine.*.*?.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_pester";
    $detectedMessage = "Detects code execution via Pester.bat (Pester - Powershell Modulte for testing) ";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\powershell.exe" -and $_.message -match "CommandLine.*.*Pester.*" -and $_.message -match "CommandLine.*.*Get-Help.*") -or ($_.ID -eq "1" -and $_.message -match "Image.*.*\cmd.exe" -and $_.message -match "CommandLine.*.*pester.*" -and $_.message -match "CommandLine.*.*;.*" -and ($_.message -match "CommandLine.*.*help.*" -or $_.message -match "CommandLine.*.*?.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
