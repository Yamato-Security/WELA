# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "8" -and $_.message -match "StartModule.*.*\kernel32.dll" -and $_.message -match "StartFunction.*LoadLibraryA") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_createremotethread_loadlibrary";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_createremotethread_loadlibrary";
            $detectedMessage = "Detects potential use of CreateRemoteThread api and LoadLibrary function to inject DLL into a process";
            $result = $event |  where { ($_.ID -eq "8" -and $_.message -match "StartModule.*.*\\kernel32.dll" -and $_.message -match "StartFunction.*LoadLibraryA") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
