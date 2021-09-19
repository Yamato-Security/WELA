# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {((($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Expand-Archive.*") -or ($_.ID -eq "4103" -and $_.message -match "Payload.*.*Expand-Archive.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_decompress_commands";
    $detectedMessage = "A General detection for specific decompress commands in PowerShell logs. This could be an adversary decompressing files.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {((($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Expand-Archive.*") -or ($_.ID -eq "4103" -and $_.message -match "Payload.*.*Expand-Archive.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
