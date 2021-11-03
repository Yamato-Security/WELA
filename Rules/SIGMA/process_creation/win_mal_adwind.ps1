# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*\\AppData\\Roaming\\Oracle" -and $_.message -match "CommandLine.*.*\\java" -and $_.message -match "CommandLine.*.*.exe ") -or ($_.message -match "CommandLine.*.*cscript.exe" -and $_.message -match "CommandLine.*.*Retrive" -and $_.message -match "CommandLine.*.*.vbs "))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { (($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\\AppData\\Roaming\\Oracle\\bin\\java" -and $_.message -match "TargetFilename.*.*.exe") -or ($_.message -match "TargetFilename.*.*\\Retrive" -and $_.message -match "TargetFilename.*.*.vbs"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -and $_.message -match "Details.*%AppData%\\Roaming\\Oracle\\bin\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_mal_adwind";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_mal_adwind";
            $detectedMessage = "Detects javaw.exe in AppData folder as used by Adwind / JRAT";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*\\AppData\\Roaming\\Oracle" -and $_.message -match "CommandLine.*.*\\java" -and $_.message -match "CommandLine.*.*.exe ") -or ($_.message -match "CommandLine.*.*cscript.exe" -and $_.message -match "CommandLine.*.*Retrive" -and $_.message -match "CommandLine.*.*.vbs "))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { (($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\\AppData\\Roaming\\Oracle\\bin\\java" -and $_.message -match "TargetFilename.*.*.exe") -or ($_.message -match "TargetFilename.*.*\\Retrive" -and $_.message -match "TargetFilename.*.*.vbs"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -and $_.message -match "Details.*%AppData%\\Roaming\\Oracle\\bin\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
