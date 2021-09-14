# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\csc.exe" -and ($_.message -match "CommandLine.*.*\AppData\.*" -or $_.message -match "CommandLine.*.*\Windows\Temp\.*")) -and  -not ($_.message -match "ParentImage.*C:\Program Files.*" -or ($_.message -match "ParentImage.*.*\sdiagnhost.exe" -or $_.message -match "ParentImage.*.*\w3wp.exe") -or ($_.message -match "ParentCommandLine.*.*\ProgramData\Microsoft\Windows Defender Advanced Threat Protection.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_csc_folder";
    $detectedMessage = "Detects a suspicious execution of csc.exe, which uses a source in a suspicious folder (e.g. AppData)";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\csc.exe" -and ($_.message -match "CommandLine.*.*\AppData\.*" -or $_.message -match "CommandLine.*.*\Windows\Temp\.*")) -and -not ($_.message -match "ParentImage.*C:\Program Files.*" -or ($_.message -match "ParentImage.*.*\sdiagnhost.exe" -or $_.message -match "ParentImage.*.*\w3wp.exe") -or ($_.message -match "ParentCommandLine.*.*\ProgramData\Microsoft\Windows Defender Advanced Threat Protection.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
