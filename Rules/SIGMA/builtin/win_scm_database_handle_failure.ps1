# Get-WinEvent -LogName Security | where {(($_.ID -eq "4656" -and $_.message -match "ObjectType.*SC_MANAGER OBJECT" -and $_.message -match "ObjectName.*servicesactive" -and $_.message -match "Keywords.*Audit Failure") -and  -not ($_.message -match "SubjectLogonId.*0x3e4")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_scm_database_handle_failure";
    $detectedMessage = "Detects non-system users failing to get a handle of the SCM database.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4656" -and $_.message -match "ObjectType.*SC_MANAGER OBJECT" -and $_.message -match "ObjectName.*servicesactive" -and $_.message -match "Keywords.*Audit Failure") -and -not ($_.message -match "SubjectLogonId.*0x3e4")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
