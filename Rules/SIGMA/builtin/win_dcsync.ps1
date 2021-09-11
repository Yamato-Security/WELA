# Get-WinEvent -LogName Security | where {(((($_.ID -eq "4662" -and ($_.message -match "Properties.*.*Replicating Directory Changes All.*" -or $_.message -match "Properties.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*")) -and  -not ($_.message -match "SubjectDomainName.*Window Manager")) -and  -not (($_.message -match "SubjectUserName.*NT AUTHORITY.*" -or $_.message -match "SubjectUserName.*MSOL_.*"))) -and  -not (($_.message -match "SubjectUserName.*.*$"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_dcsync";
    $detectedMessage = "Detects Mimikatz DC sync security events";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(((($_.ID -eq "4662" -and ($_.message -match "Properties.*.*Replicating Directory Changes All.*" -or $_.message -match "Properties.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*")) -and -not ($_.message -match "SubjectDomainName.*Window Manager")) -and -not (($_.message -match "SubjectUserName.*NT AUTHORITY.*" -or $_.message -match "SubjectUserName.*MSOL_.*"))) -and -not (($_.message -match "SubjectUserName.*.*$"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
