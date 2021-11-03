# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\regedit.exe" -and ($_.message -match "ParentImage.*.*\\TrustedInstaller.exe" -or $_.message -match "ParentImage.*.*\\ProcessHacker.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_regedit_trustedinstaller";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_susp_regedit_trustedinstaller";
                    $detectedMessage = "Detects a regedit started with TrustedInstaller privileges or by ProcessHacker.exe";
                $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\regedit.exe" -and ($_.message -match "ParentImage.*.*\\TrustedInstaller.exe" -or $_.message -match "ParentImage.*.*\\ProcessHacker.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
