# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-Service .*" -or $_.message -match "ScriptBlockText.*.*Get-ChildItem .*" -or $_.message -match "ScriptBlockText.*.*Get-Process .*") -and $_.message -match "ScriptBlockText.*.*> $env:TEMP\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "powershell_suspicious_recon";
    $detectedMessage = "Once established within a system or network, an adversary may use automated techniques for collecting internal data"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-Service .*" -or $_.message -match "ScriptBlockText.*.*Get-ChildItem .*" -or $_.message -match "ScriptBlockText.*.*Get-Process .*") -and $_.message -match "ScriptBlockText.*.*> $env:TEMP\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}