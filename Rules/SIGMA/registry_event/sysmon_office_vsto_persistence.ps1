# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "EventType.*SetValue" -and ($_.message -match "TargetObject.*.*\\Software\\Microsoft\\Office\\Outlook\\Addins\\" -or $_.message -match "TargetObject.*.*\\Software\\Microsoft\\Office\\Word\\Addins\\" -or $_.message -match "TargetObject.*.*\\Software\\Microsoft\\Office\\Excel\\Addins\\" -or $_.message -match "TargetObject.*.*\\Software\\Microsoft\\Office\\Powerpoint\\Addins\\" -or $_.message -match "TargetObject.*.*\\Software\\Microsoft\\VSTO\\Security\\Inclusion\\")) -and  -not ($_.message -match "Image.*.*\\msiexec.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_office_vsto_persistence";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_office_vsto_persistence";
            $detectedMessage = "Detects persistence via Visual Studio Tools for Office (VSTO) add-ins in Office applications.";
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "EventType.*SetValue" -and ($_.message -match "TargetObject.*.*\\Software\\Microsoft\\Office\\Outlook\\Addins\\" -or $_.message -match "TargetObject.*.*\\Software\\Microsoft\\Office\\Word\\Addins\\" -or $_.message -match "TargetObject.*.*\\Software\\Microsoft\\Office\\Excel\\Addins\\" -or $_.message -match "TargetObject.*.*\\Software\\Microsoft\\Office\\Powerpoint\\Addins\\" -or $_.message -match "TargetObject.*.*\\Software\\Microsoft\\VSTO\\Security\\Inclusion\\")) -and -not ($_.message -match "Image.*.*\\msiexec.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
