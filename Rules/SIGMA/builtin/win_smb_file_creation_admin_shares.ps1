# Get-WinEvent -LogName Security | where {(($_.ID -eq "5145" -and $_.message -match "ShareName.*.*C$" -and $_.message -match "AccessMask.*0x2") -and  -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_smb_file_creation_admin_shares";
    $detectedMessage = "Look for non-system accounts SMB accessing a file with write (0x2) access mask via administrative share (i.e C$).";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "5145" -and $_.message -match "ShareName.*.*C$" -and $_.message -match "AccessMask.*0x2") -and -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
