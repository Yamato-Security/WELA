# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "ParentCommandLine.*.*\svchost.exe.*" -and $_.message -match "ParentCommandLine.*.*termsvcs.*") -and  -not ($_.message -match "Image.*.*\rdpclip.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_termserv_proc_spawn";
    $detectedMessage = "Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ($_.message -match "ParentCommandLine.*.*\svchost.exe.*" -and $_.message -match "ParentCommandLine.*.*termsvcs.*") -and -not ($_.message -match "Image.*.*\rdpclip.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}