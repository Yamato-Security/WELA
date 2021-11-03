# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "Image.*\outlook.exe" -and $_.message -match "TargetFilename.*.*\appdata\local\microsoft\FORMS\") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_outlook_newform";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_outlook_newform";
            $detectedMessage = "Detects the creation of new Outlook form which can contain malicious code";
            $result = $event |  where { ($_.ID -eq "11" -and $_.message -match "Image.*\\outlook.exe" -and $_.message -match "TargetFilename.*.*\\appdata\\local\\microsoft\\FORMS\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
