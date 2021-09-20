# Get-WinEvent -LogName Security | where {(($_.ID -eq "4769" -and $_.message -match "TicketOptions.*0x40810000" -and $_.message -match "TicketEncryptionType.*0x17") -and  -not ($_.message -match "ServiceName.*$.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_rc4_kerberos";
    $detectedMessage = "Detects service ticket requests using RC4 encryption type";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4769" -and $_.message -match "TicketOptions.*0x40810000" -and $_.message -match "TicketEncryptionType.*0x17") -and -not ($_.message -match "ServiceName.*$.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
