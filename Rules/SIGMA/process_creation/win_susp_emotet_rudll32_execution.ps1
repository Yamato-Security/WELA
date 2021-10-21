# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\rundll32.exe") -and ($_.message -match "CommandLine.*.*,RunDLL")) -and  -not (($_.message -match "ParentImage.*.*\\tracker.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_emotet_rudll32_execution";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_emotet_rudll32_execution";
            $detectedMessage = "Detecting Emotet DLL loading by looking for rundll32.exe processes with command lines ending in ,RunDLL or ,#1";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\rundll32.exe") -and ($_.message -match "CommandLine.*.*,RunDLL")) -and -not (($_.message -match "ParentImage.*.*\\tracker.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
