# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\\csc.exe" -and ($_.message -match "CommandLine.*.*\\AppData\\" -or $_.message -match "CommandLine.*.*\\Windows\\Temp\\")) -and  -not ($_.message -match "ParentImage.*C:\\Program Files" -or ($_.message -match "ParentImage.*.*\\sdiagnhost.exe" -or $_.message -match "ParentImage.*.*\\w3wp.exe") -or ($_.message -match "ParentCommandLine.*.*\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_csc_folder";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_csc_folder";
            $detectedMessage = "Detects a suspicious execution of csc.exe, which uses a source in a suspicious folder (e.g. AppData)";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\csc.exe" -and ($_.message -match "CommandLine.*.*\\AppData\\" -or $_.message -match "CommandLine.*.*\\Windows\\Temp\\")) -and -not ($_.message -match "ParentImage.*C:\\Program Files" -or ($_.message -match "ParentImage.*.*\\sdiagnhost.exe" -or $_.message -match "ParentImage.*.*\\w3wp.exe") -or ($_.message -match "ParentCommandLine.*.*\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
