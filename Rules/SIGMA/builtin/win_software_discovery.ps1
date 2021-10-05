# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*get-itemProperty.*" -and $_.message -match "ScriptBlockText.*.*\\software\\.*" -and $_.message -match "ScriptBlockText.*.*select-object.*" -and $_.message -match "ScriptBlockText.*.*format-table.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\reg.exe" -and $_.message -match "CommandLine.*.*query.*" -and $_.message -match "CommandLine.*.*\\software\\.*" -and $_.message -match "CommandLine.*.*/v.*" -and $_.message -match "CommandLine.*.*svcversion.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_software_discovery";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_software_discovery";
            $detectedMessage = "Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable."
            $results = @();
            $results += $event | where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*get-itemProperty.*" -and $_.message -match "ScriptBlockText.*.*\\software\\.*" -and $_.message -match "ScriptBlockText.*.*select-object.*" -and $_.message -match "ScriptBlockText.*.*format-table.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\reg.exe" -and $_.message -match "CommandLine.*.*query.*" -and $_.message -match "CommandLine.*.*\\software\\.*" -and $_.message -match "CommandLine.*.*/v.*" -and $_.message -match "CommandLine.*.*svcversion.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;    
                    Write-Host $result;
                    Write-Host
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
