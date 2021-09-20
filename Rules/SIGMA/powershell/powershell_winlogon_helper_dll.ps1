# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*CurrentVersion\Winlogon.*" -and ($_.message -match "ScriptBlockText.*.*Set-ItemProperty.*" -or $_.message -match "ScriptBlockText.*.*New-Item.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_winlogon_helper_dll";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "powershell_winlogon_helper_dll";
                $result = $event |  where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*CurrentVersion\\Winlogon.*" -and ($_.message -match "ScriptBlockText.*.*Set-ItemProperty.*" -or $_.message -match "ScriptBlockText.*.*New-Item.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
