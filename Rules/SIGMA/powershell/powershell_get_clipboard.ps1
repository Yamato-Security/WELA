# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {((($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Get-Clipboard.*") -or ($_.ID -eq "4103" -and $_.message -match "Payload.*.*Get-Clipboard.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_get_clipboard";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_get_clipboard";
            $detectedMessage = "A General detection for the Get-Clipboard commands in PowerShell logs. This could be an adversary capturing clipboard contents.";
            $result = $event |  where { ((($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Get-Clipboard.*") -or ($_.ID -eq "4103" -and $_.message -match "Payload.*.*Get-Clipboard.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    $ruleStack.Add($ruleName, $detectRule);
}
