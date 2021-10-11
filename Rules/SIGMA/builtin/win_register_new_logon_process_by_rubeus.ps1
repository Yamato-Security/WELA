# Get-WinEvent -LogName Security | where {($_.ID -eq "4611" -and $_.message -match "LogonProcessName.*User32LogonProcesss") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_register_new_logon_process_by_rubeus";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_register_new_logon_process_by_rubeus";
            $detectedMessage = "Detects potential use of Rubeus via registered new trusted logon process";
            $result = $event |  where { ($_.ID -eq "4611" -and $_.message -match "LogonProcessName.*User32LogonProcesss") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
