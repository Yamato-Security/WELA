# Get-WinEvent -LogName Microsoft-Windows-Windows Defender/Operational | where { (($_.ID -eq "5007") -and ($_.message -match "New Value.*.*\\Microsoft\\Windows Defender\\Exclusions")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.ID -eq "13") -and ($_.message -match "TargetObject.*.*\\Microsoft\\Windows Defender\\Exclusions")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_defender_exclusions";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "win_defender_exclusions";
            $detectedMessage = "Detects the Setting of Windows Defender Exclusions";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { (($_.ID -eq "5007") -and ($_.message -match "New Value.*.*\\Microsoft\\Windows Defender\\Exclusions")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            [void]$results.Add($tmp);
            $tmp = $event | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.ID -eq "13") -and ($_.message -match "TargetObject.*.*\\Microsoft\\Windows Defender\\Exclusions")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;    
                    Write-Output $result;
                    Write-Output ""; 
                }
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
