# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\VBoxDrvInst.exe" -and $_.message -match "CommandLine.*.*driver.*" -and $_.message -match "CommandLine.*.*executeinf.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_vboxdrvInst";
    $detectedMessage = "Detect VBoxDrvInst.exe run whith parameters allowing processing INF file. This allows to create values in the registry and install drivers."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\VBoxDrvInst.exe" -and $_.message -match "CommandLine.*.*driver.*" -and $_.message -match "CommandLine.*.*executeinf.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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