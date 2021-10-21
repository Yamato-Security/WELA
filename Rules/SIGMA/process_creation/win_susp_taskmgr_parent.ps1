# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\\taskmgr.exe" -and  -not (($_.message -match "Image.*.*\\resmon.exe" -or $_.message -match "Image.*.*\\mmc.exe" -or $_.message -match "Image.*.*\\taskmgr.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_taskmgr_parent";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_taskmgr_parent";
            $detectedMessage = "Detects the creation of a process from Windows task manager";
            $result = $event |  where { (($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\\taskmgr.exe" -and -not (($_.message -match "Image.*.*\\resmon.exe" -or $_.message -match "Image.*.*\\mmc.exe" -or $_.message -match "Image.*.*\\taskmgr.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
