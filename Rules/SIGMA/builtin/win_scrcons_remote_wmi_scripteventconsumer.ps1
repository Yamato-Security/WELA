# Get-WinEvent -LogName Security | where {(($_.ID -eq "4624" -and $_.message -match "LogonType.*3" -and $_.message -match "ProcessName.*.*scrcons.exe") -and  -not ($_.message -match "TargetLogonId.*0x3e7")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_scrcons_remote_wmi_scripteventconsumer";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_scrcons_remote_wmi_scripteventconsumer";
            $detectedMessage = "Detect potential adversaries leveraging WMI ActiveScriptEventConsumers remotely to move laterally in a network";
            $result = $event |  where { (($_.ID -eq "4624" -and $_.message -match "LogonType.*3" -and $_.message -match "ProcessName.*.*scrcons.exe") -and -not ($_.message -match "TargetLogonId.*0x3e7")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
