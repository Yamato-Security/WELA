# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "ParentCommandLine.*.*\\svchost.exe" -and $_.message -match "ParentCommandLine.*.*termsvcs") -and  -not ($_.message -match "Image.*.*\\rdpclip.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_termserv_proc_spawn";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_termserv_proc_spawn";
            $detectedMessage = "Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "ParentCommandLine.*.*\\svchost.exe" -and $_.message -match "ParentCommandLine.*.*termsvcs") -and -not ($_.message -match "Image.*.*\\rdpclip.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
