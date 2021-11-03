# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*wuauclt" -or $_.message -match "OriginalFileName.*wuauclt.exe") -and ($_.message -match "CommandLine.*.*UpdateDeploymentProvider" -and $_.message -match "CommandLine.*.*.dll" -and $_.message -match "CommandLine.*.*RunHandlerComServer")) -and  -not (($_.message -match "CommandLine.*.* /UpdateDeploymentProvider UpdateDeploymentProvider.dll " -or $_.message -match "CommandLine.*.* wuaueng.dll "))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_proxy_execution_wuauclt";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_proxy_execution_wuauclt";
            $detectedMessage = "Detects the use of the Windows Update Client binary (wuauclt.exe) to proxy execute code.";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*wuauclt" -or $_.message -match "OriginalFileName.*wuauclt.exe") -and ($_.message -match "CommandLine.*.*UpdateDeploymentProvider" -and $_.message -match "CommandLine.*.*.dll" -and $_.message -match "CommandLine.*.*RunHandlerComServer")) -and -not (($_.message -match "CommandLine.*.* /UpdateDeploymentProvider UpdateDeploymentProvider.dll " -or $_.message -match "CommandLine.*.* wuaueng.dll "))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
