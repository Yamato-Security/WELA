# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ProcessCommandLine.*.*/UpdateDeploymentProvider.*" -and $_.message -match "ProcessCommandLine.*.*/RunHandlerComServer.*" -and ($_.message -match "Image.*.*\wuauclt.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_wuauclt";
    $detectedMessage = "Detects code execution via the Windows Update client (wuauclt)";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "ProcessCommandLine.*.*/UpdateDeploymentProvider.*" -and $_.message -match "ProcessCommandLine.*.*/RunHandlerComServer.*" -and ($_.message -match "Image.*.*\wuauclt.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
