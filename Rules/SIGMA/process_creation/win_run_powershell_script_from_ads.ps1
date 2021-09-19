# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\powershell.exe" -and $_.message -match "Image.*.*\powershell.exe" -and $_.message -match "CommandLine.*.*Get-Content.*" -and $_.message -match "CommandLine.*.*-Stream.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_run_powershell_script_from_ads";
    $detectedMessage = "Detects PowerShell script execution from Alternate Data Stream (ADS)";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\powershell.exe" -and $_.message -match "Image.*.*\powershell.exe" -and $_.message -match "CommandLine.*.*Get-Content.*" -and $_.message -match "CommandLine.*.*-Stream.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
