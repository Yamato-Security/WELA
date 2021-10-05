# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ProcessCommandLine.*.*/UpdateDeploymentProvider.*" -and $_.message -match "ProcessCommandLine.*.*/RunHandlerComServer.*" -and ($_.message -match "Image.*.*\\wuauclt.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_wuauclt";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_wuauclt";
            $detectedMessage = "Detects code execution via the Windows Update client (wuauclt)";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "ProcessCommandLine.*.*/UpdateDeploymentProvider.*" -and $_.message -match "ProcessCommandLine.*.*/RunHandlerComServer.*" -and ($_.message -match "Image.*.*\\wuauclt.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
