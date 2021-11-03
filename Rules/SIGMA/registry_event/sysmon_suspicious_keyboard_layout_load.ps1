# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\Keyboard Layout\\Preload\\" -or $_.message -match "TargetObject.*.*\\Keyboard Layout\\Substitutes\\") -and ($_.message -match "Details.*.*00000429" -or $_.message -match "Details.*.*00050429" -or $_.message -match "Details.*.*0000042a")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_suspicious_keyboard_layout_load";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_suspicious_keyboard_layout_load";
            $detectedMessage = "Detects the keyboard preload installation with a suspicious keyboard layout, e.g. Chinese, Iranian or Vietnamese layout load in user session on systems";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\Keyboard Layout\\Preload\\" -or $_.message -match "TargetObject.*.*\\Keyboard Layout\\Substitutes\\") -and ($_.message -match "Details.*.*00000429" -or $_.message -match "Details.*.*00050429" -or $_.message -match "Details.*.*0000042a")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
