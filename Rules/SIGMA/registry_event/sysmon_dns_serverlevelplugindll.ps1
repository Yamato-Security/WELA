# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\\services\\DNS\\Parameters\\ServerLevelPluginDll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\dnscmd.exe" -and $_.message -match "CommandLine.*.*/config.*" -and $_.message -match "CommandLine.*.*/serverlevelplugindll.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_dns_serverlevelplugindll";
    $detectedMessage = "Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\\services\\DNS\\Parameters\\ServerLevelPluginDll") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\dnscmd.exe" -and $_.message -match "CommandLine.*.*/config.*" -and $_.message -match "CommandLine.*.*/serverlevelplugindll.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
