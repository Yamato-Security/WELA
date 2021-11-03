# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*-Recurse" -and $_.message -match "ScriptBlockText.*.*|" -and $_.message -match "ScriptBlockText.*.*Compress-Archive") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_data_compressed";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_data_compressed";
            $detectedMessage = "An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.";
            $result = $event |  where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*-Recurse" -and $_.message -match "ScriptBlockText.*.*|" -and $_.message -match "ScriptBlockText.*.*Compress-Archive") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
