# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*\cmd.exe /C whoami.*" -and $_.message -match "ParentImage.*C:\Temp.*") -or ($_.message -match "CommandLine.*.*conhost.exe 0xffffffff -ForceV1.*" -and ($_.message -match "ParentCommandLine.*.*/C whoami.*" -or $_.message -match "ParentCommandLine.*.*cmd.exe /C echo.*" -or $_.message -match "ParentCommandLine.*.* > \.\pipe.*")) -or (($_.message -match "CommandLine.*.*cmd.exe /c echo.*" -or $_.message -match "CommandLine.*.*> \.\pipe.*" -or $_.message -match "CommandLine.*.*\whoami.exe.*") -and $_.message -match "ParentImage.*.*\dllhost.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_cobaltstrike_process_patterns";
    $detectedMessage = "Detects process patterns found in Cobalt Strike beacon activity (see reference for more details)";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*\cmd.exe /C whoami.*" -and $_.message -match "ParentImage.*C:\Temp.*") -or ($_.message -match "CommandLine.*.*conhost.exe 0xffffffff -ForceV1.*" -and ($_.message -match "ParentCommandLine.*.*/C whoami.*" -or $_.message -match "ParentCommandLine.*.*cmd.exe /C echo.*" -or $_.message -match "ParentCommandLine.*.* > \.\pipe.*")) -or (($_.message -match "CommandLine.*.*cmd.exe /c echo.*" -or $_.message -match "CommandLine.*.*> \.\pipe.*" -or $_.message -match "CommandLine.*.*\whoami.exe.*") -and $_.message -match "ParentImage.*.*\dllhost.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
