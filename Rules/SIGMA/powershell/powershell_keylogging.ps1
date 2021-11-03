# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-Keystrokes" -or ($_.message -match "ScriptBlockText.*.*Get-ProcAddress user32.dll GetAsyncKeyState" -and $_.message -match "ScriptBlockText.*.*Get-ProcAddress user32.dll GetForegroundWindow"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_keylogging";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_keylogging";
            $detectedMessage = "Adversaries may log user keystrokes to intercept credentials as the user types them.";
            $result = $event |  where { ($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-Keystrokes" -or ($_.message -match "ScriptBlockText.*.*Get-ProcAddress user32.dll GetAsyncKeyState" -and $_.message -match "ScriptBlockText.*.*Get-ProcAddress user32.dll GetForegroundWindow"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
