# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\\rundll32.exe" -or $_.message -match "CommandLine.*.*\\regsvcs.exe" -or $_.message -match "CommandLine.*.*\\regasm.exe" -or $_.message -match "CommandLine.*.*\\regsvr32.exe") -and  -not (($_.message -match "ParentImage.*.*\\AppData\\Local\\" -or $_.message -match "ParentImage.*.*\\Microsoft\\Edge\\"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_procs_req_dlls";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_procs_req_dlls";
            $detectedMessage = "Detects suspicious start of program that usually requires a DLL as parameter, which can be a sign of process injection or hollowing activity";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\\rundll32.exe" -or $_.message -match "CommandLine.*.*\\regsvcs.exe" -or $_.message -match "CommandLine.*.*\\regasm.exe" -or $_.message -match "CommandLine.*.*\\regsvr32.exe") -and -not (($_.message -match "ParentImage.*.*\\AppData\\Local\\" -or $_.message -match "ParentImage.*.*\\Microsoft\\Edge\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
