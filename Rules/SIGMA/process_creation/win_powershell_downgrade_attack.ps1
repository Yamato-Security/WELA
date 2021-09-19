# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -version 2 .*" -or $_.message -match "CommandLine.*.* -versio 2 .*" -or $_.message -match "CommandLine.*.* -versi 2 .*" -or $_.message -match "CommandLine.*.* -vers 2 .*" -or $_.message -match "CommandLine.*.* -ver 2 .*" -or $_.message -match "CommandLine.*.* -ve 2 .*") -and $_.message -match "Image.*.*\powershell.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_powershell_downgrade_attack";
    $detectedMessage = "Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -version 2 .*" -or $_.message -match "CommandLine.*.* -versio 2 .*" -or $_.message -match "CommandLine.*.* -versi 2 .*" -or $_.message -match "CommandLine.*.* -vers 2 .*" -or $_.message -match "CommandLine.*.* -ver 2 .*" -or $_.message -match "CommandLine.*.* -ve 2 .*") -and $_.message -match "Image.*.*\powershell.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
