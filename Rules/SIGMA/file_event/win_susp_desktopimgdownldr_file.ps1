# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11") -and (($_.message -match "Image.*.*svchost.exe" -and $_.message -match "TargetFilename.*.*\Personalization\LockScreenImage\") -and  -not ($_.message -match "TargetFilename.*.*C:\Windows\")) -and  -not (($_.message -match "TargetFilename.*.*.jpg" -or $_.message -match "TargetFilename.*.*.jpeg" -or $_.message -match "TargetFilename.*.*.png"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_desktopimgdownldr_file";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_desktopimgdownldr_file";
            $detectedMessage = "Detects a suspicious Microsoft desktopimgdownldr file creation that stores a file to a suspicious location or contains a file with a suspicious extension";
            $result = $event |  where { (($_.ID -eq "11") -and (($_.message -match "Image.*.*svchost.exe" -and $_.message -match "TargetFilename.*.*\\Personalization\\LockScreenImage\\") -and -not ($_.message -match "TargetFilename.*.*C:\\Windows\\")) -and -not (($_.message -match "TargetFilename.*.*.jpg" -or $_.message -match "TargetFilename.*.*.jpeg" -or $_.message -match "TargetFilename.*.*.png"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
