# Get-WinEvent -LogName Security | where {($_.ID -eq "4719" -and ($_.message -match "AuditPolicyChanges.*.*%%8448" -or $_.message -match "AuditPolicyChanges.*.*%%8450")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_disable_event_logging";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_disable_event_logging";
            $detectedMessage = "Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario where an entity would want to bypass local logging to evade detection when windows event logging is enabled and reviewed. Also, it is recommended to turn off ""Local Group Policy Object Processing"" via GPO, which will make sure that Active Directory GPOs take precedence over local/edited computer policies via something such as ""gpedit.msc"". Please note, that disabling ""Local Group Policy Object Processing"" may cause an issue in scenarios of one off specific GPO modifications -- however it is recommended to perform these modifications in Active Directory anyways.";
            $result = $event |  where { ($_.ID -eq "4719" -and ($_.message -match "AuditPolicyChanges.*.*%%8448" -or $_.message -match "AuditPolicyChanges.*.*%%8450")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
