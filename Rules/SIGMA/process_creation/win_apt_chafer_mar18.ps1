# Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and ($_.message -match "SC Scheduled Scan" -or $_.message -match "UpdatMachine")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Security | where {($_.ID -eq "4698" -and ($_.message -match "SC Scheduled Scan" -or $_.message -match "UpdatMachine")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UMe" -or $_.message -match "TargetObject.*.*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UT")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*\\Service.exe" -and ($_.message -match "CommandLine.*.*i" -or $_.message -match "CommandLine.*.*u")) -or ($_.message -match "CommandLine.*.*\\microsoft\\Taskbar\\autoit3.exe" -or $_.message -match "CommandLine.*C:\\wsc.exe") -or ($_.message -match "Image.*.*\\Windows\\Temp\\DB\\" -and $_.message -match "Image.*.*.exe") -or ($_.message -match "CommandLine.*.*\\nslookup.exe" -and $_.message -match "CommandLine.*.*-q=TXT" -and $_.message -match "ParentImage.*.*\\Autoit"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message


function Add-Rule {

    $ruleName = "win_apt_chafer_mar18";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_chafer_mar18";
            $detectedMessage = "Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.ID -eq "7045" -and ($_.message -match "SC Scheduled Scan" -or $_.message -match "UpdatMachine")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "4698" -and ($_.message -match "SC Scheduled Scan" -or $_.message -match "UpdatMachine")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UMe" -or $_.message -match "TargetObject.*.*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UT")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*\\Service.exe" -and ($_.message -match "CommandLine.*.*i" -or $_.message -match "CommandLine.*.*u")) -or ($_.message -match "CommandLine.*.*\\microsoft\\Taskbar\\autoit3.exe" -or $_.message -match "CommandLine.*C:\\wsc.exe") -or ($_.message -match "Image.*.*\\Windows\\Temp\\DB\\" -and $_.message -match "Image.*.*.exe") -or ($_.message -match "CommandLine.*.*\\nslookup.exe" -and $_.message -match "CommandLine.*.*-q=TXT" -and $_.message -match "ParentImage.*.*\\Autoit"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
