# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.* /INJECTRUNNING.*" -and $_.message -match "CommandLine.*.*.dll.*" -and $_.message -match "OriginalFileName.*.*mavinject.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_creation_mavinject_dll";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_creation_mavinject_dll";
                    $detectedMessage = "Injects arbitrary DLL into running process specified by process ID. Requires Windows 10.";
                $result = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.* /INJECTRUNNING.*" -and $_.message -match "CommandLine.*.*.dll.*" -and $_.message -match "OriginalFileName.*.*mavinject.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
