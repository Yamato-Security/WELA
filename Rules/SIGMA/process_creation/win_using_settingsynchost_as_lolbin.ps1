# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and  -not (($_.message -match "Image.*C:\\Windows\\System32\\.*" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\.*")) -and ($_.message -match "ParentCommandLine.*.*cmd.exe /c.*" -and $_.message -match "ParentCommandLine.*.*RoamDiag.cmd.*" -and $_.message -match "ParentCommandLine.*.*-outputpath.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_using_settingsynchost_as_lolbin";
    $detectedMessage = "Detects using SettingSyncHost.exe to run hijacked binary";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and -not (($_.message -match "Image.*C:\\Windows\\System32\\.*" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\.*")) -and ($_.message -match "ParentCommandLine.*.*cmd.exe /c.*" -and $_.message -match "ParentCommandLine.*.*RoamDiag.cmd.*" -and $_.message -match "ParentCommandLine.*.*-outputpath.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
