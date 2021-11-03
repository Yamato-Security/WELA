#Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*Invoke-WebRequest" -or $_.message -match "CommandLine.*.*iwr " -or $_.message -match "CommandLine.*.*wget " -or $_.message -match "CommandLine.*.*curl " -or $_.message -match "CommandLine.*.*Net.WebClient" -or $_.message -match "CommandLine.*.*Start-BitsTransfer")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
#Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Invoke-WebRequest" -or $_.message -match "ScriptBlockText.*.*iwr " -or $_.message -match "ScriptBlockText.*.*wget " -or $_.message -match "ScriptBlockText.*.*curl " -or $_.message -match "ScriptBlockText.*.*Net.WebClient" -or $_.message -match "ScriptBlockText.*.*Start-BitsTransfer")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_powershell_web_request";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "win_powershell_web_request";
            $detectedMessage = "Detects the use of various web request methods (including aliases) via Windows PowerShell";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*Invoke-WebRequest" -or $_.message -match "CommandLine.*.*iwr " -or $_.message -match "CommandLine.*.*wget " -or $_.message -match "CommandLine.*.*curl " -or $_.message -match "CommandLine.*.*Net.WebClient" -or $_.message -match "CommandLine.*.*Start-BitsTransfer")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Invoke-WebRequest" -or $_.message -match "ScriptBlockText.*.*iwr " -or $_.message -match "ScriptBlockText.*.*wget " -or $_.message -match "ScriptBlockText.*.*curl " -or $_.message -match "ScriptBlockText.*.*Net.WebClient" -or $_.message -match "ScriptBlockText.*.*Start-BitsTransfer")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
