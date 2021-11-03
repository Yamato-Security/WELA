# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and (($_.message -match "Image.*.*\\tracker.exe") -or ($_.message -match "Tracker")) -and ($_.message -match "CommandLine.*.* /d ") -and ($_.message -match "CommandLine.*.* /c ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_tracker_execution";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_tracker_execution";
            $detectedMessage = "This rule detects DLL injection and execution via LOLBAS - Tracker.exe";
            $result = $event | where { ($_.ID -eq "1" -and ($_.ID -eq "1") -and (($_.message -match "Image.*.*\\tracker.exe") -or ($_.message -match "Tracker")) -and ($_.message -match "CommandLine.*.* /d ") -and ($_.message -match "CommandLine.*.* /c ")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
