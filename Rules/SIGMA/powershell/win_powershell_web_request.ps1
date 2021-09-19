Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*Invoke-WebRequest.*" -or $_.message -match "CommandLine.*.*iwr .*" -or $_.message -match "CommandLine.*.*wget .*" -or $_.message -match "CommandLine.*.*curl .*" -or $_.message -match "CommandLine.*.*Net.WebClient.*" -or $_.message -match "CommandLine.*.*Start-BitsTransfer.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Invoke-WebRequest.*" -or $_.message -match "ScriptBlockText.*.*iwr .*" -or $_.message -match "ScriptBlockText.*.*wget .*" -or $_.message -match "ScriptBlockText.*.*curl .*" -or $_.message -match "ScriptBlockText.*.*Net.WebClient.*" -or $_.message -match "ScriptBlockText.*.*Start-BitsTransfer.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_powershell_web_request";
    $detectedMessage = "Detects the use of various web request methods (including aliases) via Windows PowerShell";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*Invoke-WebRequest.*" -or $_.message -match "CommandLine.*.*iwr .*" -or $_.message -match "CommandLine.*.*wget .*" -or $_.message -match "CommandLine.*.*curl .*" -or $_.message -match "CommandLine.*.*Net.WebClient.*" -or $_.message -match "CommandLine.*.*Start-BitsTransfer.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Invoke-WebRequest.*" -or $_.message -match "ScriptBlockText.*.*iwr .*" -or $_.message -match "ScriptBlockText.*.*wget .*" -or $_.message -match "ScriptBlockText.*.*curl .*" -or $_.message -match "ScriptBlockText.*.*Net.WebClient.*" -or $_.message -match "ScriptBlockText.*.*Start-BitsTransfer.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
