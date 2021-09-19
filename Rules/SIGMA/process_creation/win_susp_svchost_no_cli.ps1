# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*svchost.exe" -and $_.message -match "Image.*.*\\svchost.exe") -and  -not (($_.message -match "ParentImage.*.*\\rpcnet.exe" -or $_.message -match "ParentImage.*.*\\rpcnetp.exe") -or -not CommandLine="*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_svchost_no_cli";
    $detectedMessage = "It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*svchost.exe" -and $_.message -match "Image.*.*\\svchost.exe") -and -not (($_.message -match "ParentImage.*.*\\rpcnet.exe" -or $_.message -match "ParentImage.*.*\\rpcnetp.exe") -or -not $_.message -match "CommandLine.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
