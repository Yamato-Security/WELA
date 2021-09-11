# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-Keystrokes.*" -or ($_.message -match "ScriptBlockText.*.*Get-ProcAddress user32.dll GetAsyncKeyState.*" -and $_.message -match "ScriptBlockText.*.*Get-ProcAddress user32.dll GetForegroundWindow.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "powershell_keylogging";
    $detectedMessage = "Adversaries may log user keystrokes to intercept credentials as the user types them.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-Keystrokes.*" -or ($_.message -match "ScriptBlockText.*.*Get-ProcAddress user32.dll GetAsyncKeyState.*" -and $_.message -match "ScriptBlockText.*.*Get-ProcAddress user32.dll GetForegroundWindow.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
