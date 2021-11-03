# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*HKU\\" -and $_.message -match "TargetObject.*.*\\mscfile\\shell\\open\\command") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\\eventvwr.exe" -and  -not ($_.message -match "Image.*.*\\mmc.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_uac_bypass_eventvwr";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "sysmon_uac_bypass_eventvwr";
            $detectedMessage = "Detects UAC bypass method using Windows event viewer";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*HKU\\" -and $_.message -match "TargetObject.*.*\\mscfile\\shell\\open\\command") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { (($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\\eventvwr.exe" -and -not ($_.message -match "Image.*.*\\mmc.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
