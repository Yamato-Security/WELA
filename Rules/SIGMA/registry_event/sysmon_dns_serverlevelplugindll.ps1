# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\\services\\DNS\\Parameters\\ServerLevelPluginDll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\dnscmd.exe" -and $_.message -match "CommandLine.*.*/config.*" -and $_.message -match "CommandLine.*.*/serverlevelplugindll.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_dns_serverlevelplugindll";
    $detectedMessage = "Detects the installation of a plugin DLL via ServerLevelPluginDll parameter in Registry, which can be used to execute code in context of the DNS server"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "TargetObject.*.*\\services\\DNS\\Parameters\\ServerLevelPluginDll") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $result2 = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\dnscmd.exe" -and $_.message -match "CommandLine.*.*/config.*" -and $_.message -match "CommandLine.*.*/serverlevelplugindll.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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