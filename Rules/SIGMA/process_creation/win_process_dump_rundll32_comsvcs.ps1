# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*comsvcs.dll,#24.*" -or $_.message -match "CommandLine.*.*comsvcs.dll,MiniDump.*" -or $_.message -match "CommandLine.*.*comsvcs.dll MiniDump.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_process_dump_rundll32_comsvcs";
    $detectedMessage = "Detects a process memory dump performed via ordinal function 24 in comsvcs.dll";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*comsvcs.dll,#24.*" -or $_.message -match "CommandLine.*.*comsvcs.dll,MiniDump.*" -or $_.message -match "CommandLine.*.*comsvcs.dll MiniDump.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
