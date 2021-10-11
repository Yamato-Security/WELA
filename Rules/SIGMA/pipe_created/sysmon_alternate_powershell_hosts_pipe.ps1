# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "17" -or $_.ID -eq "18")) -and $_.message -match "PipeName.*\PSHost.*" -and  -not (($_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\powershell_ise.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_alternate_powershell_hosts_pipe";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_alternate_powershell_hosts_pipe";
            $detectedMessage = "Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe";
            $result = $event |  where { ((($_.ID -eq "17" -or $_.ID -eq "18")) -and $_.message -match "PipeName.*\\PSHost.*" -and -not (($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\powershell_ise.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
