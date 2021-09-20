# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\rundll32.exe" -or $_.message -match "OriginalFileName.*RUNDLL32.EXE") -and ($_.message -match "CommandLine.*.*comsvcs.*" -and $_.message -match "CommandLine.*.*MiniDump.*" -and $_.message -match "CommandLine.*.*full.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_comsvcs_procdump";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_susp_comsvcs_procdump";
                    $detectedMessage = "Detects process memory dump via comsvcs.dll and rundll32";
                $result = $event |  where { ($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\rundll32.exe" -or $_.message -match "OriginalFileName.*RUNDLL32.EXE") -and ($_.message -match "CommandLine.*.*comsvcs.*" -and $_.message -match "CommandLine.*.*MiniDump.*" -and $_.message -match "CommandLine.*.*full.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
