# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*rundll32.exe.*" -or $_.message -match "Image.*.*cmd.exe.*") -and ($_.message -match "CommandLine.*.*gthread-3.6.dll.*" -or $_.message -match "CommandLine.*.*\\Windows\\Temp\\tmp.bat.*" -or $_.message -match "CommandLine.*.*sigcmm-2.4.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_redmimicry_winnti_proc";
    $detectedMessage = "Detects actions caused by the RedMimicry Winnti playbook";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*rundll32.exe.*" -or $_.message -match "Image.*.*cmd.exe.*") -and ($_.message -match "CommandLine.*.*gthread-3.6.dll.*" -or $_.message -match "CommandLine.*.*\\Windows\\Temp\\tmp.bat.*" -or $_.message -match "CommandLine.*.*sigcmm-2.4.dll.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
