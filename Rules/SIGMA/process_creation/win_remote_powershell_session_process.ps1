# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\\wsmprovhost.exe" -or $_.message -match "ParentImage.*.*\\wsmprovhost.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_remote_powershell_session_process";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_remote_powershell_session_process";
            $detectedMessage = "Detects remote PowerShell sections by monitoring for wsmprovhost (WinRM host process) as a parent or child process (sign of an active PowerShell remote session).";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\wsmprovhost.exe" -or $_.message -match "ParentImage.*.*\\wsmprovhost.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
