# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "Image.*.*\\Downloads\\" -or $_.message -match "Image.*.*\\Temporary Internet Files\\Content.Outlook\\" -or $_.message -match "Image.*.*\\Local Settings\\Temporary Internet Files\\") -and $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_download_run_key";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_download_run_key";
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "Image.*.*\\Downloads\\" -or $_.message -match "Image.*.*\\Temporary Internet Files\\Content.Outlook\\" -or $_.message -match "Image.*.*\\Local Settings\\Temporary Internet Files\\") -and $_.message -match "TargetObject.*.*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
