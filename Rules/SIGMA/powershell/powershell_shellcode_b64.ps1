# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*AAAAYInlM.*" -and ($_.message -match "ScriptBlockText.*.*OiCAAAAYInlM.*" -or $_.message -match "ScriptBlockText.*.*OiJAAAAYInlM.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "powershell_shellcode_b64";
    $detectedMessage = "Detects Base64 encoded Shellcode";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*AAAAYInlM.*" -and ($_.message -match "ScriptBlockText.*.*OiCAAAAYInlM.*" -or $_.message -match "ScriptBlockText.*.*OiJAAAAYInlM.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
