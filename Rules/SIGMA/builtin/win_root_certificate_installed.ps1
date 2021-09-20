#Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Cert:\\LocalMachine\\Root.*" -and ($_.message -match "ScriptBlockText.*.*Move-Item.*" -or $_.message -match "ScriptBlockText.*.*Import-Certificate.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
#Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*root.*" -and (($_.message -match "Image.*.*\\certutil.exe" -and $_.message -match "CommandLine.*.*-addstore.*") -or ($_.message -match "Image.*.*\\CertMgr.exe" -and $_.message -match "CommandLine.*.*/add.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_root_certificate_installed";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event | where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Cert:\\LocalMachine\\Root.*" -and ($_.message -match "ScriptBlockText.*.*Move-Item.*" -or $_.message -match "ScriptBlockText.*.*Import-Certificate.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*root.*" -and (($_.message -match "Image.*.*\\certutil.exe" -and $_.message -match "CommandLine.*.*-addstore.*") -or ($_.message -match "Image.*.*\\CertMgr.exe" -and $_.message -match "CommandLine.*.*/add.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
