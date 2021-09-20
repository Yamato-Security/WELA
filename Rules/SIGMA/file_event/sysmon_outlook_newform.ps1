# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "Image.*\outlook.exe" -and $_.message -match "TargetFilename.*.*\appdata\local\microsoft\FORMS\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_outlook_newform";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_outlook_newform";
            $detectedMessage = "Detects the creation of new Outlook form which can contain malicious code";
            $result = $event |  where { ($_.ID -eq "11" -and $_.message -match "Image.*\\outlook.exe" -and $_.message -match "TargetFilename.*.*\\appdata\\local\\microsoft\\FORMS\\.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
