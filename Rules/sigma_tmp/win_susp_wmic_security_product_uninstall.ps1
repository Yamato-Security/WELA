# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*wmic.*" -and $_.message -match "CommandLine.*.*product where name=.*" -and $_.message -match "CommandLine.*.*call uninstall.*" -and $_.message -match "CommandLine.*.*/nointeractive.*" -and ($_.message -match "CommandLine.*.*Antivirus.*" -or $_.message -match "CommandLine.*.*Endpoint Security.*" -or $_.message -match "CommandLine.*.*Endpoint Detection.*" -or $_.message -match "CommandLine.*.*Crowdstrike Sensor.*" -or $_.message -match "CommandLine.*.*Windows Defender.*" -or $_.message -match "CommandLine.*.*VirusScan.*" -or $_.message -match "CommandLine.*.*Threat Protection.*" -or $_.message -match "CommandLine.*.*Endpoint Sensor.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_wmic_security_product_uninstall";
    $detectedMessage = "Detects deinstallation of security products using WMIC utility"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | !firstpipe!
            if ($result.Count -ne 0) {
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
