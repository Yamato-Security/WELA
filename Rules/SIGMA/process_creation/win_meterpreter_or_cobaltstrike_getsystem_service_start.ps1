# $event | where {(($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\services.exe" -and (($_.message -match "CommandLine.*.*cmd.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*echo.*" -and $_.message -match "CommandLine.*.*\pipe\.*") -or ($_.message -match "CommandLine.*.*%COMSPEC%.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*echo.*" -and $_.message -match "CommandLine.*.*\pipe\.*") -or ($_.message -match "CommandLine.*.*cmd.exe.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*echo.*" -and $_.message -match "CommandLine.*.*\pipe\.*") -or ($_.message -match "CommandLine.*.*rundll32.*" -and $_.message -match "CommandLine.*.*.dll,a.*" -and $_.message -match "CommandLine.*.*/p:.*"))) -and  -not ($_.message -match "CommandLine.*.*MpCmdRun.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_meterpreter_or_cobaltstrike_getsystem_service_start";
    $detectedMessage = "Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\services.exe" -and (($_.message -match "CommandLine.*.*cmd.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*echo.*" -and $_.message -match "CommandLine.*.*\pipe\.*") -or ($_.message -match "CommandLine.*.*%COMSPEC%.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*echo.*" -and $_.message -match "CommandLine.*.*\pipe\.*") -or ($_.message -match "CommandLine.*.*cmd.exe.*" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*echo.*" -and $_.message -match "CommandLine.*.*\pipe\.*") -or ($_.message -match "CommandLine.*.*rundll32.*" -and $_.message -match "CommandLine.*.*.dll,a.*" -and $_.message -match "CommandLine.*.*/p:.*"))) -and -not ($_.message -match "CommandLine.*.*MpCmdRun.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
