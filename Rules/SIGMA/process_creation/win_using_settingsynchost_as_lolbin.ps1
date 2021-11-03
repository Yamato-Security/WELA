# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and  -not (($_.message -match "Image.*C:\\Windows\\System32\\" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\")) -and ($_.message -match "ParentCommandLine.*.*cmd.exe /c" -and $_.message -match "ParentCommandLine.*.*RoamDiag.cmd" -and $_.message -match "ParentCommandLine.*.*-outputpath")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_using_settingsynchost_as_lolbin";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_using_settingsynchost_as_lolbin";
                    $detectedMessage = "Detects using SettingSyncHost.exe to run hijacked binary";
                $result = $event | where { (($_.ID -eq "1") -and -not (($_.message -match "Image.*C:\\Windows\\System32\\" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\")) -and ($_.message -match "ParentCommandLine.*.*cmd.exe /c" -and $_.message -match "ParentCommandLine.*.*RoamDiag.cmd" -and $_.message -match "ParentCommandLine.*.*-outputpath")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
