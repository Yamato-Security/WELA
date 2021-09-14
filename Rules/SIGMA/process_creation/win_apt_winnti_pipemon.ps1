# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*setup0.exe -p.*") -or ($_.message -match "CommandLine.*.*setup.exe.*" -and ($_.message -match "CommandLine.*.*-x:0" -or $_.message -match "CommandLine.*.*-x:1" -or $_.message -match "CommandLine.*.*-x:2")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_winnti_pipemon";
    $detectedMessage = "Detects specific process characteristics of Winnti Pipemon malware reported by ESET";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*setup0.exe -p.*") -or ($_.message -match "CommandLine.*.*setup.exe.*" -and ($_.message -match "CommandLine.*.*-x:0" -or $_.message -match "CommandLine.*.*-x:1" -or $_.message -match "CommandLine.*.*-x:2")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
