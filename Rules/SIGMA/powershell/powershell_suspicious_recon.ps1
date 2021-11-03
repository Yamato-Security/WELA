# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-Service " -or $_.message -match "ScriptBlockText.*.*Get-ChildItem " -or $_.message -match "ScriptBlockText.*.*Get-Process ") -and $_.message -match "ScriptBlockText.*.*> $env:TEMP\") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_suspicious_recon";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_suspicious_recon";
            $detectedMessage = "Once established within a system or network, an adversary may use automated techniques for collecting internal data";
            $result = $event |  where { ($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-Service " -or $_.message -match "ScriptBlockText.*.*Get-ChildItem " -or $_.message -match "ScriptBlockText.*.*Get-Process ") -and $_.message -match "ScriptBlockText.*.*> $env:TEMP\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
