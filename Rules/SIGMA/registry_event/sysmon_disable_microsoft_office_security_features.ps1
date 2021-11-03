# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*SetValue" -and $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Office\\" -and ($_.message -match "TargetObject.*.*VBAWarnings" -or $_.message -match "TargetObject.*.*DisableInternetFilesInPV" -or $_.message -match "TargetObject.*.*DisableUnsafeLocationsInPV" -or $_.message -match "TargetObject.*.*DisableAttachementsInPV") -and $_.message -match "Details.*DWORD (0x00000001)") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_disable_microsoft_office_security_features";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_disable_microsoft_office_security_features";
            $detectedMessage = "Disable Microsoft Office Security Features by registry";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*SetValue" -and $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Office\\" -and ($_.message -match "TargetObject.*.*VBAWarnings" -or $_.message -match "TargetObject.*.*DisableInternetFilesInPV" -or $_.message -match "TargetObject.*.*DisableUnsafeLocationsInPV" -or $_.message -match "TargetObject.*.*DisableAttachementsInPV") -and $_.message -match "Details.*DWORD (0x00000001)") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
