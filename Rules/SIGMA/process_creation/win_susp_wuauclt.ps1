# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ProcessCommandLine.*.*/UpdateDeploymentProvider" -and $_.message -match "ProcessCommandLine.*.*/RunHandlerComServer" -and ($_.message -match "Image.*.*\\wuauclt.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_wuauclt";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_wuauclt";
            $detectedMessage = "Detects code execution via the Windows Update client (wuauclt)";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "ProcessCommandLine.*.*/UpdateDeploymentProvider" -and $_.message -match "ProcessCommandLine.*.*/RunHandlerComServer" -and ($_.message -match "Image.*.*\\wuauclt.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
