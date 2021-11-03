# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*Software\\Microsoft\\Office\\" -or $_.message -match "TargetObject.*.*\\Outlook\\Today\\") -and (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ((($_.message -match "TargetObject.*.*Stamp") -and $_.message -match "Details.*DWORD (0x00000001)") -or ($_.message -match "TargetObject.*.*UserDefinedUrl"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_outlook_registry_todaypage";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_outlook_registry_todaypage";
            $detectedMessage = "Detects the manipulation of persistant URLs which could execute malicious code";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*Software\\Microsoft\\Office\\" -or $_.message -match "TargetObject.*.*\\Outlook\\Today\\") -and (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ((($_.message -match "TargetObject.*.*Stamp") -and $_.message -match "Details.*DWORD (0x00000001)") -or ($_.message -match "TargetObject.*.*UserDefinedUrl"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
