# Get-WinEvent -LogName Security | where {(($_.ID -eq "4769" -and $_.message -match "TicketOptions.*0x40810000" -and $_.message -match "TicketEncryptionType.*0x17") -and  -not ($_.message -match "ServiceName.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_rc4_kerberos";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_rc4_kerberos";
            $detectedMessage = "Detects service ticket requests using RC4 encryption type";
            $result = $event |  where { (($_.ID -eq "4769" -and $_.message -match "TicketOptions.*0x40810000" -and $_.message -match "TicketEncryptionType.*0x17") -and -not ($_.message -match "ServiceName.*$")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
