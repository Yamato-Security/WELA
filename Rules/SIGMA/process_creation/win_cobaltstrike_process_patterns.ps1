# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*\cmd.exe /C whoami" -and $_.message -match "ParentImage.*C:\Temp") -or ($_.message -match "CommandLine.*.*conhost.exe 0xffffffff -ForceV1" -and ($_.message -match "ParentCommandLine.*.*/C whoami" -or $_.message -match "ParentCommandLine.*.*cmd.exe /C echo" -or $_.message -match "ParentCommandLine.*.* > \.\pipe")) -or (($_.message -match "CommandLine.*.*cmd.exe /c echo" -or $_.message -match "CommandLine.*.*> \.\pipe" -or $_.message -match "CommandLine.*.*\whoami.exe") -and $_.message -match "ParentImage.*.*\dllhost.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_cobaltstrike_process_patterns";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_cobaltstrike_process_patterns";
            $detectedMessage = "Detects process patterns found in Cobalt Strike beacon activity (see reference for more details)";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*\\cmd.exe /C whoami" -and $_.message -match "ParentImage.*C:\\Temp") -or ($_.message -match "CommandLine.*.*conhost.exe 0xffffffff -ForceV1" -and ($_.message -match "ParentCommandLine.*.*/C whoami" -or $_.message -match "ParentCommandLine.*.*cmd.exe /C echo" -or $_.message -match "ParentCommandLine.*.* > \\.\\pipe")) -or (($_.message -match "CommandLine.*.*cmd.exe /c echo" -or $_.message -match "CommandLine.*.*> \\.\\pipe" -or $_.message -match "CommandLine.*.*\\whoami.exe") -and $_.message -match "ParentImage.*.*\\dllhost.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
