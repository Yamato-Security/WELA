# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*reg" -and $_.message -match "CommandLine.*.*add" -and $_.message -match "CommandLine.*.* /d 4" -and $_.message -match "CommandLine.*.* /v Start" -and ($_.message -match "CommandLine.*.*\\Sense " -or $_.message -match "CommandLine.*.*\\WinDefend" -or $_.message -match "CommandLine.*.*\\MsMpSvc" -or $_.message -match "CommandLine.*.*\\NisSrv" -or $_.message -match "CommandLine.*.*\\WdBoot " -or $_.message -match "CommandLine.*.*\\WdNisDrv" -or $_.message -match "CommandLine.*.*\\WdNisSvc" -or $_.message -match "CommandLine.*.*\\wscsvc " -or $_.message -match "CommandLine.*.*\\SecurityHealthService" -or $_.message -match "CommandLine.*.*\\wuauserv" -or $_.message -match "CommandLine.*.*\\UsoSvc ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_reg_disable_sec_services";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_reg_disable_sec_services";
            $detectedMessage = "Detects a suspicious reg.exe invocation that looks as if it would disable an important security service";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*reg" -and $_.message -match "CommandLine.*.*add" -and $_.message -match "CommandLine.*.* /d 4" -and $_.message -match "CommandLine.*.* /v Start" -and ($_.message -match "CommandLine.*.*\\Sense " -or $_.message -match "CommandLine.*.*\\WinDefend" -or $_.message -match "CommandLine.*.*\\MsMpSvc" -or $_.message -match "CommandLine.*.*\\NisSrv" -or $_.message -match "CommandLine.*.*\\WdBoot " -or $_.message -match "CommandLine.*.*\\WdNisDrv" -or $_.message -match "CommandLine.*.*\\WdNisSvc" -or $_.message -match "CommandLine.*.*\\wscsvc " -or $_.message -match "CommandLine.*.*\\SecurityHealthService" -or $_.message -match "CommandLine.*.*\\wuauserv" -or $_.message -match "CommandLine.*.*\\UsoSvc ")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
