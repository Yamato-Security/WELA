# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*reg.*" -and $_.message -match "CommandLine.*.*add.*") -or ($_.message -match "CommandLine.*.*powershell.*" -and ($_.message -match "CommandLine.*.*set-itemproperty.*" -or $_.message -match "CommandLine.*.* sp .*" -or $_.message -match "CommandLine.*.*new-itemproperty.*"))) -and $_.message -match "CommandLine.*.*ControlSet.*" -and $_.message -match "CommandLine.*.*Services.*" -and ($_.message -match "CommandLine.*.*ImagePath.*" -or $_.message -match "CommandLine.*.*FailureCommand.*" -or $_.message -match "CommandLine.*.*ServiceDLL.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_non_priv_reg_or_ps";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_non_priv_reg_or_ps";
            $detectedMessage = "Search for usage of reg or Powershell by non-priveleged users to modify service configuration in registry";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*reg.*" -and $_.message -match "CommandLine.*.*add.*") -or ($_.message -match "CommandLine.*.*powershell.*" -and ($_.message -match "CommandLine.*.*set-itemproperty.*" -or $_.message -match "CommandLine.*.* sp .*" -or $_.message -match "CommandLine.*.*new-itemproperty.*"))) -and $_.message -match "CommandLine.*.*ControlSet.*" -and $_.message -match "CommandLine.*.*Services.*" -and ($_.message -match "CommandLine.*.*ImagePath.*" -or $_.message -match "CommandLine.*.*FailureCommand.*" -or $_.message -match "CommandLine.*.*ServiceDLL.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
