# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*AAAAYInlM.*" -and ($_.message -match "ScriptBlockText.*.*OiCAAAAYInlM.*" -or $_.message -match "ScriptBlockText.*.*OiJAAAAYInlM.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_shellcode_b64";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_shellcode_b64";
            $detectedMessage = "Detects Base64 encoded Shellcode";
            $result = $event |  where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*AAAAYInlM.*" -and ($_.message -match "ScriptBlockText.*.*OiCAAAAYInlM.*" -or $_.message -match "ScriptBlockText.*.*OiJAAAAYInlM.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
