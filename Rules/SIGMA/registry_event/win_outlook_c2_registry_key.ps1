# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Outlook\\Security\\Level" -and $_.message -match "Details.*.*0x00000001") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_outlook_c2_registry_key";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_outlook_c2_registry_key";
            $detectedMessage = "Detects the modification of Outlook Security Setting to allow unprompted execution. Goes with win_outlook_c2_macro_creation.yml and is particularly interesting if both events occur near to each other.";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Outlook\\Security\\Level" -and $_.message -match "Details.*.*0x00000001") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
