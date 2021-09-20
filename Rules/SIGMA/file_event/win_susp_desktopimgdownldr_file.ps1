# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11") -and (($_.message -match "Image.*.*svchost.exe" -and $_.message -match "TargetFilename.*.*\Personalization\LockScreenImage\.*") -and  -not ($_.message -match "TargetFilename.*.*C:\Windows\.*")) -and  -not (($_.message -match "TargetFilename.*.*.jpg.*" -or $_.message -match "TargetFilename.*.*.jpeg.*" -or $_.message -match "TargetFilename.*.*.png.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_desktopimgdownldr_file";
    $detectedMessage = "Detects a suspicious Microsoft desktopimgdownldr file creation that stores a file to a suspicious location or contains a file with a suspicious extension";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "11") -and (($_.message -match "Image.*.*svchost.exe" -and $_.message -match "TargetFilename.*.*\\Personalization\\LockScreenImage\\.*") -and -not ($_.message -match "TargetFilename.*.*C:\\Windows\\.*")) -and -not (($_.message -match "TargetFilename.*.*.jpg.*" -or $_.message -match "TargetFilename.*.*.jpeg.*" -or $_.message -match "TargetFilename.*.*.png.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
