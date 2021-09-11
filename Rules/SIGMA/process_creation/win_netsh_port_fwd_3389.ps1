# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\netsh.exe" -and $_.message -match "CommandLine.*.*i.*" -and $_.message -match "CommandLine.*.* p.*" -and $_.message -match "CommandLine.*.*=3389.*" -and $_.message -match "CommandLine.*.* c.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_netsh_port_fwd_3389";
    $detectedMessage = "Detects netsh commands that configure a port forwarding of port 3389 used for RDP";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\netsh.exe" -and $_.message -match "CommandLine.*.*i.*" -and $_.message -match "CommandLine.*.* p.*" -and $_.message -match "CommandLine.*.*=3389.*" -and $_.message -match "CommandLine.*.* c.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
