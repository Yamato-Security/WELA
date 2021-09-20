# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "8" -and $_.message -match "StartModule.*.*\kernel32.dll" -and $_.message -match "StartFunction.*LoadLibraryA") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_createremotethread_loadlibrary";
    $detectedMessage = "Detects potential use of CreateRemoteThread api and LoadLibrary function to inject DLL into a process";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "8" -and $_.message -match "StartModule.*.*\\kernel32.dll" -and $_.message -match "StartFunction.*LoadLibraryA") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
