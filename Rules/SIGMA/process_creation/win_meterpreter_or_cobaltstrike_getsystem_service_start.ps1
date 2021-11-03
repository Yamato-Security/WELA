# $event | where {(($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\services.exe" -and (($_.message -match "CommandLine.*.*cmd" -and $_.message -match "CommandLine.*.*/c" -and $_.message -match "CommandLine.*.*echo" -and $_.message -match "CommandLine.*.*\pipe\") -or ($_.message -match "CommandLine.*.*%COMSPEC%" -and $_.message -match "CommandLine.*.*/c" -and $_.message -match "CommandLine.*.*echo" -and $_.message -match "CommandLine.*.*\pipe\") -or ($_.message -match "CommandLine.*.*cmd.exe" -and $_.message -match "CommandLine.*.*/c" -and $_.message -match "CommandLine.*.*echo" -and $_.message -match "CommandLine.*.*\pipe\") -or ($_.message -match "CommandLine.*.*rundll32" -and $_.message -match "CommandLine.*.*.dll,a" -and $_.message -match "CommandLine.*.*/p:"))) -and  -not ($_.message -match "CommandLine.*.*MpCmdRun")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_meterpreter_or_cobaltstrike_getsystem_service_start";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_meterpreter_or_cobaltstrike_getsystem_service_start";
            $result = $event | where { (($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\\services.exe" -and (($_.message -match "CommandLine.*.*cmd" -and $_.message -match "CommandLine.*.*/c" -and $_.message -match "CommandLine.*.*echo" -and $_.message -match "CommandLine.*.*\\pipe\\") -or ($_.message -match "CommandLine.*.*%COMSPEC%" -and $_.message -match "CommandLine.*.*/c" -and $_.message -match "CommandLine.*.*echo" -and $_.message -match "CommandLine.*.*\\pipe\\") -or ($_.message -match "CommandLine.*.*cmd.exe" -and $_.message -match "CommandLine.*.*/c" -and $_.message -match "CommandLine.*.*echo" -and $_.message -match "CommandLine.*.*\\pipe\\") -or ($_.message -match "CommandLine.*.*rundll32" -and $_.message -match "CommandLine.*.*.dll,a" -and $_.message -match "CommandLine.*.*/p:"))) -and -not ($_.message -match "CommandLine.*.*MpCmdRun")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
