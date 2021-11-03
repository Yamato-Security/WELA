#Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Cert:\\LocalMachine\\Root" -and ($_.message -match "ScriptBlockText.*.*Move-Item" -or $_.message -match "ScriptBlockText.*.*Import-Certificate")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
#Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*root" -and (($_.message -match "Image.*.*\\certutil.exe" -and $_.message -match "CommandLine.*.*-addstore") -or ($_.message -match "Image.*.*\\CertMgr.exe" -and $_.message -match "CommandLine.*.*/add"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_root_certificate_installed";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_root_certificate_installed";
            $detectedMessage = "Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers."
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Cert:\\LocalMachine\\Root" -and ($_.message -match "ScriptBlockText.*.*Move-Item" -or $_.message -match "ScriptBlockText.*.*Import-Certificate")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*root" -and (($_.message -match "Image.*.*\\certutil.exe" -and $_.message -match "CommandLine.*.*-addstore") -or ($_.message -match "Image.*.*\\CertMgr.exe" -and $_.message -match "CommandLine.*.*/add"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
