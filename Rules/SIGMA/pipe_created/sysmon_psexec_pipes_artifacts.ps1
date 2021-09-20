# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "PipeName.*psexec.*" -or $_.message -match "PipeName.*paexec.*" -or $_.message -match "PipeName.*remcom.*" -or $_.message -match "PipeName.*csexec.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_psexec_pipes_artifacts";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_psexec_pipes_artifacts";
                $result = $event |  where { (($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "PipeName.*psexec.*" -or $_.message -match "PipeName.*paexec.*" -or $_.message -match "PipeName.*remcom.*" -or $_.message -match "PipeName.*csexec.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
