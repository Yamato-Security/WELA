# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*gthread-3.6.dll.*" -or $_.message -match "TargetFilename.*.*sigcmm-2.4.dll.*" -or $_.message -match "TargetFilename.*.*\Windows\Temp\tmp.bat.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_redmimicry_winnti_filedrop";
    $detectedMessage = "Detects actions caused by the RedMimicry Winnti playbook";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*gthread-3.6.dll.*" -or $_.message -match "TargetFilename.*.*sigcmm-2.4.dll.*" -or $_.message -match "TargetFilename.*.*\Windows\Temp\tmp.bat.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
