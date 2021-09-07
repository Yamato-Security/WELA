#Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Cert:\\LocalMachine\\Root.*" -and ($_.message -match "ScriptBlockText.*.*Move-Item.*" -or $_.message -match "ScriptBlockText.*.*Import-Certificate.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
#Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*root.*" -and (($_.message -match "Image.*.*\\certutil.exe" -and $_.message -match "CommandLine.*.*-addstore.*") -or ($_.message -match "Image.*.*\\CertMgr.exe" -and $_.message -match "CommandLine.*.*/add.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_root_certificate_installed";
    $detectedMessage = "Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Cert:\\LocalMachine\\Root.*" -and ($_.message -match "ScriptBlockText.*.*Move-Item.*" -or $_.message -match "ScriptBlockText.*.*Import-Certificate.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $result2 = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*root.*" -and (($_.message -match "Image.*.*\\certutil.exe" -and $_.message -match "CommandLine.*.*-addstore.*") -or ($_.message -match "Image.*.*\\CertMgr.exe" -and $_.message -match "CommandLine.*.*/add.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            if (($result.Count -ne 0) -or ($result2.Count -ne 0)) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
