# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*Software\\Microsoft\\Office\\" -or $_.message -match "TargetObject.*.*Outlook\\WebView\\") -and $_.message -match "TargetObject.*.*URL" -and ($_.message -match "TargetObject.*.*Calendar" -or $_.message -match "TargetObject.*.*Inbox")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_outlook_registry_webview";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_outlook_registry_webview";
            $detectedMessage = "Detects the manipulation of persistant URLs which can be malicious";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*Software\\Microsoft\\Office\\" -or $_.message -match "TargetObject.*.*Outlook\\WebView\\") -and $_.message -match "TargetObject.*.*URL" -and ($_.message -match "TargetObject.*.*Calendar" -or $_.message -match "TargetObject.*.*Inbox")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
