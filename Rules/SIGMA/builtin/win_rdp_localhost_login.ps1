# Get-WinEvent -LogName Security | where {($_.ID -eq "4624" -and $_.message -match "LogonType.*10" -and ($_.message -match "::1" -or $_.message -match "127.0.0.1")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_rdp_localhost_login";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_rdp_localhost_login";
            $detectedMessage = "RDP login with localhost source address may be a tunnelled login";
            $result = $event |  where { ($_.ID -eq "4624" -and $_.message -match "LogonType.*10" -and ($_.message -match "::1" -or $_.message -match "127.0.0.1")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
