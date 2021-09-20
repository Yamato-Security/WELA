# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*CL_Invocation.ps1.*" -and $_.message -match "ScriptBlockText.*.*SyncInvoke.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_CL_Invocation_LOLScript";
    $detectedMessage = "Detects Execution via SyncInvoke in CL_Invocation.ps1 module";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*CL_Invocation.ps1.*" -and $_.message -match "ScriptBlockText.*.*SyncInvoke.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
