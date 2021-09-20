# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and $_.message -match "TargetObject.*.*\\Software\\Microsoft\\WAB\\DLLPath" -and  -not ($_.message -match "Details.*%CommonProgramFiles%\\System\\wab32.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_wab_dllpath_reg_change";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_wab_dllpath_reg_change";
                    $detectedMessage = "This rule detects that the path to the DLL written in the registry is different from the default one. Launched WAB.exe tries to load the DLL from Registry.";
                $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and $_.message -match "TargetObject.*.*\\Software\\Microsoft\\WAB\\DLLPath" -and -not ($_.message -match "Details.*%CommonProgramFiles%\\System\\wab32.dll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
