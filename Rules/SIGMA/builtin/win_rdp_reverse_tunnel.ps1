# Get-WinEvent -LogName Security | where {($_.ID -eq "5156" -and (($_.message -match "SourcePort.*3389" -and ($_.message -match "DestAddress.*127..*" -or $_.message -match "::1")) -or ($_.message -match "DestPort.*3389" -and ($_.message -match "SourceAddress.*127..*" -or $_.message -match "::1")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_rdp_reverse_tunnel";
    $detectedMessage = "Detects svchost hosting RDP termsvcs communicating with the loopback address";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "5156" -and (($_.message -match "SourcePort.*3389" -and ($_.message -match "DestAddress.*127..*" -or $_.message -match "::1")) -or ($_.message -match "DestPort.*3389" -and ($_.message -match "SourceAddress.*127..*" -or $_.message -match "::1")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
