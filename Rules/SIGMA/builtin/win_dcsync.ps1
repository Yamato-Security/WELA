# Get-WinEvent -LogName Security | where {(((($_.ID -eq "4662" -and ($_.message -match "Properties.*.*Replicating Directory Changes All" -or $_.message -match "Properties.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")) -and  -not ($_.message -match "SubjectDomainName.*Window Manager")) -and  -not (($_.message -match "SubjectUserName.*NT AUTHORITY" -or $_.message -match "SubjectUserName.*MSOL_"))) -and  -not (($_.message -match "SubjectUserName.*.*$"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_dcsync";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_dcsync";
            $detectedMessage = "Detects Mimikatz DC sync security events";
            $result = $event |  where { (((($_.ID -eq "4662" -and ($_.message -match "Properties.*.*Replicating Directory Changes All" -or $_.message -match "Properties.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")) -and -not ($_.message -match "SubjectDomainName.*Window Manager")) -and -not (($_.message -match "SubjectUserName.*NT AUTHORITY" -or $_.message -match "SubjectUserName.*MSOL_"))) -and -not (($_.message -match "SubjectUserName.*.*$"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
