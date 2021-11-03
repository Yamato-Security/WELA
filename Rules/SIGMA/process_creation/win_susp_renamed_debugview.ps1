# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Sysinternals DebugView" -or $_.message -match "Sysinternals Debugview") -and  -not ($_.message -match "OriginalFileName.*Dbgview.exe" -and $_.message -match "Image.*.*\\Dbgview.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_renamed_debugview";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_renamed_debugview";
            $detectedMessage = "Detects suspicious renamed SysInternals DebugView execution";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Sysinternals DebugView" -or $_.message -match "Sysinternals Debugview") -and -not ($_.message -match "OriginalFileName.*Dbgview.exe" -and $_.message -match "Image.*.*\\Dbgview.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
