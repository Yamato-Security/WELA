# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "PipeName.*.*\lsadump.*" -or $_.message -match "PipeName.*.*\cachedump.*" -or $_.message -match "PipeName.*.*\wceservicepipe.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_cred_dump_tools_named_pipes";
    $detectedMessage = "Detects well-known credential dumping tools execution via specific named pipes";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "PipeName.*.*\\lsadump.*" -or $_.message -match "PipeName.*.*\\cachedump.*" -or $_.message -match "PipeName.*.*\\wceservicepipe.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
