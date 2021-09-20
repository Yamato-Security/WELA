# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Sysinternals DebugView" -or $_.message -match "Sysinternals Debugview") -and  -not ($_.message -match "OriginalFileName.*Dbgview.exe" -and $_.message -match "Image.*.*\\Dbgview.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_renamed_debugview";
    $detectedMessage = "Detects suspicious renamed SysInternals DebugView execution";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Sysinternals DebugView" -or $_.message -match "Sysinternals Debugview") -and -not ($_.message -match "OriginalFileName.*Dbgview.exe" -and $_.message -match "Image.*.*\\Dbgview.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
