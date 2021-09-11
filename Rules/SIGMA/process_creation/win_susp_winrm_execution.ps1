# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\cscript.exe" -and $_.message -match "CommandLine.*.*winrm.*" -and $_.message -match "CommandLine.*.*invoke Create wmicimv2/Win32_.*" -and $_.message -match "CommandLine.*.*-r:http.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_winrm_execution";
    $detectedMessage = "Detects an attempt to execude code or create service on remote host via winrm.vbs.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\cscript.exe" -and $_.message -match "CommandLine.*.*winrm.*" -and $_.message -match "CommandLine.*.*invoke Create wmicimv2/Win32_.*" -and $_.message -match "CommandLine.*.*-r:http.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
