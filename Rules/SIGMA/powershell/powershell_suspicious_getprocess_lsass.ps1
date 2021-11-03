# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Get-Process lsass") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_suspicious_getprocess_lsass";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_suspicious_getprocess_lsass";
            $detectedMessage = "Detects a Get-Process command on lsass process, which is in almost all cases a sign of malicious activity";
            $result = $event |  where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Get-Process lsass") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
