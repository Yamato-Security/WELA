# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*svchost.exe" -and $_.message -match "Image.*.*\\svchost.exe") -and  -not (($_.message -match "ParentImage.*.*\\rpcnet.exe" -or $_.message -match "ParentImage.*.*\\rpcnetp.exe") -or -not CommandLine="*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_svchost_no_cli";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_svchost_no_cli";
            $detectedMessage = "It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*svchost.exe" -and $_.message -match "Image.*.*\\svchost.exe") -and -not (($_.message -match "ParentImage.*.*\\rpcnet.exe" -or $_.message -match "ParentImage.*.*\\rpcnetp.exe") -or -not $_.message -match "CommandLine.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
