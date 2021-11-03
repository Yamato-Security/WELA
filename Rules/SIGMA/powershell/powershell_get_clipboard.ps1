# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {((($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Get-Clipboard") -or ($_.ID -eq "4103" -and $_.message -match "Payload.*.*Get-Clipboard"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_get_clipboard";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_get_clipboard";
            $detectedMessage = "A General detection for the Get-Clipboard commands in PowerShell logs. This could be an adversary capturing clipboard contents.";
            $result = $event |  where { ((($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Get-Clipboard") -or ($_.ID -eq "4103" -and $_.message -match "Payload.*.*Get-Clipboard"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
