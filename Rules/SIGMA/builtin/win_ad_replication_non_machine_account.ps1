# Get-WinEvent -LogName Security | where {(($_.ID -eq "4662" -and $_.message -match "AccessMask.*0x100" -and ($_.message -match "Properties.*.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.message -match "Properties.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or $_.message -match "Properties.*.*89e95b76-444d-4c62-991a-0facbeda640c")) -and  -not ($_.message -match "SubjectUserName.*.*$" -or $_.message -match "SubjectUserName.*MSOL_")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_ad_replication_non_machine_account";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_ad_replication_non_machine_account";
            $detectedMessage = "Detects potential abuse of Active Directory Replication Service (ADRS) from a non machine account to request credentials.";
            $result = $event |  where { (($_.ID -eq "4662" -and $_.message -match "AccessMask.*0x100" -and ($_.message -match "Properties.*.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.message -match "Properties.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or $_.message -match "Properties.*.*89e95b76-444d-4c62-991a-0facbeda640c")) -and -not ($_.message -match "SubjectUserName.*.*$" -or $_.message -match "SubjectUserName.*MSOL_")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
