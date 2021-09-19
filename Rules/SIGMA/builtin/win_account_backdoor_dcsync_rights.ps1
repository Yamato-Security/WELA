# Get-WinEvent -LogName Security | where {($_.ID -eq "5136" -and $_.message -match "AttributeLDAPDisplayName.*ntSecurityDescriptor" -and ($_.message -match "AttributeValue.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*" -or $_.message -match "AttributeValue.*.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2.*" -or $_.message -match "AttributeValue.*.*89e95b76-444d-4c62-991a-0facbeda640c.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_account_backdoor_dcsync_rights";
    $detectedMessage = "backdooring domain object to grant the rights associated with DCSync to a regular user or machine account using PowerviewAdd-DomainObjectAcl DCSync";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "5136" -and $_.message -match "AttributeLDAPDisplayName.*ntSecurityDescriptor" -and ($_.message -match "AttributeValue.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*" -or $_.message -match "AttributeValue.*.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2.*" -or $_.message -match "AttributeValue.*.*89e95b76-444d-4c62-991a-0facbeda640c.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
