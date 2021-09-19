# Get-WinEvent -LogName Security | where {(($_.ID -eq "4662" -and $_.message -match "AccessMask.*0x100" -and ($_.message -match "Properties.*.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2.*" -or $_.message -match "Properties.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*" -or $_.message -match "Properties.*.*89e95b76-444d-4c62-991a-0facbeda640c.*")) -and  -not ($_.message -match "SubjectUserName.*.*$" -or $_.message -match "SubjectUserName.*MSOL_.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_ad_replication_non_machine_account";
    $detectedMessage = "Detects potential abuse of Active Directory Replication Service (ADRS) from a non machine account to request credentials.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4662" -and $_.message -match "AccessMask.*0x100" -and ($_.message -match "Properties.*.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2.*" -or $_.message -match "Properties.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*" -or $_.message -match "Properties.*.*89e95b76-444d-4c62-991a-0facbeda640c.*")) -and -not ($_.message -match "SubjectUserName.*.*$" -or $_.message -match "SubjectUserName.*MSOL_.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
