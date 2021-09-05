# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\rundll32.exe" -or $_.message -match "CommandLine.*.*\regsvcs.exe" -or $_.message -match "CommandLine.*.*\regasm.exe" -or $_.message -match "CommandLine.*.*\regsvr32.exe") -and  -not (($_.message -match "ParentImage.*.*\AppData\Local\.*" -or $_.message -match "ParentImage.*.*\Microsoft\Edge\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_procs_req_dlls";
    $detectedMessage = "Detects suspicious start of program that usually requires a DLL as parameter, which can be a sign of process injection or hollowing activity"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\rundll32.exe" -or $_.message -match "CommandLine.*.*\regsvcs.exe" -or $_.message -match "CommandLine.*.*\regasm.exe" -or $_.message -match "CommandLine.*.*\regsvr32.exe") -and -not (($_.message -match "ParentImage.*.*\AppData\Local\.*" -or $_.message -match "ParentImage.*.*\Microsoft\Edge\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
