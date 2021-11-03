# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "PipeName.*.*\lsadump" -or $_.message -match "PipeName.*.*\cachedump" -or $_.message -match "PipeName.*.*\wceservicepipe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_cred_dump_tools_named_pipes";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_cred_dump_tools_named_pipes";
            $detectedMessage = "Detects well-known credential dumping tools execution via specific named pipes";
            $result = $event |  where { (($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "PipeName.*.*\\lsadump" -or $_.message -match "PipeName.*.*\\cachedump" -or $_.message -match "PipeName.*.*\\wceservicepipe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
