# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*CL_Mutexverifiers.ps1" -and $_.message -match "ScriptBlockText.*.*runAfterCancelProcess") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_CL_Mutexverifiers_LOLScript";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_CL_Mutexverifiers_LOLScript";
            $detectedMessage = "Detects Execution via runAfterCancelProcess in CL_Mutexverifiers.ps1 module";
            $result = $event |  where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*CL_Mutexverifiers.ps1" -and $_.message -match "ScriptBlockText.*.*runAfterCancelProcess") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
