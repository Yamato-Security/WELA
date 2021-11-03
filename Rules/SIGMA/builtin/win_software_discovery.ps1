# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*get-itemProperty" -and $_.message -match "ScriptBlockText.*.*\\software\\" -and $_.message -match "ScriptBlockText.*.*select-object" -and $_.message -match "ScriptBlockText.*.*format-table") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\reg.exe" -and $_.message -match "CommandLine.*.*query" -and $_.message -match "CommandLine.*.*\\software\\" -and $_.message -match "CommandLine.*.*/v" -and $_.message -match "CommandLine.*.*svcversion") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_software_discovery";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_software_discovery";
            $detectedMessage = "Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable."
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*get-itemProperty" -and $_.message -match "ScriptBlockText.*.*\\software\\" -and $_.message -match "ScriptBlockText.*.*select-object" -and $_.message -match "ScriptBlockText.*.*format-table") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);

            $tmp = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\reg.exe" -and $_.message -match "CommandLine.*.*query" -and $_.message -match "CommandLine.*.*\\software\\" -and $_.message -match "CommandLine.*.*/v" -and $_.message -match "CommandLine.*.*svcversion") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
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
