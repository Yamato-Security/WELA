# Get-WinEvent -LogName Security | where {($_.ID -eq "5156" -and (($_.message -match "SourcePort.*3389" -and ($_.message -match "DestAddress.*127." -or $_.message -match "::1")) -or ($_.message -match "DestPort.*3389" -and ($_.message -match "SourceAddress.*127." -or $_.message -match "::1")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_rdp_reverse_tunnel";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_rdp_reverse_tunnel";
            $detectedMessage = "Detects svchost hosting RDP termsvcs communicating with the loopback address";
            $result = $event |  where { ($_.ID -eq "5156" -and (($_.message -match "SourcePort.*3389" -and ($_.message -match "DestAddress.*127." -or $_.message -match "::1")) -or ($_.message -match "DestPort.*3389" -and ($_.message -match "SourceAddress.*127." -or $_.message -match "::1")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
