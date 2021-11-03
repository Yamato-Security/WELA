# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentCommandLine.*.*\DllHost.exe " -and ($_.message -match "ParentCommandLine.*.*{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" -or $_.message -match "ParentCommandLine.*.*{3E000D72-A845-4CD9-BD83-80C07C3B881F}")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_cmstp_com_object_access";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_cmstp_com_object_access";
            $detectedMessage = "Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "ParentCommandLine.*.*\\DllHost.exe " -and ($_.message -match "ParentCommandLine.*.*{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" -or $_.message -match "ParentCommandLine.*.*{3E000D72-A845-4CD9-BD83-80C07C3B881F}")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
