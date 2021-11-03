# Get-WinEvent -LogName Security | where {($_.ID -eq "5136" -and $_.message -match "AttributeLDAPDisplayName.*ntSecurityDescriptor" -and ($_.message -match "AttributeValue.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or $_.message -match "AttributeValue.*.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.message -match "AttributeValue.*.*89e95b76-444d-4c62-991a-0facbeda640c")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_account_backdoor_dcsync_rights";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_account_backdoor_dcsync_rights";
            $detectedMessage = "backdooring domain object to grant the rights associated with DCSync to a regular user or machine account using PowerviewAdd-DomainObjectAcl DCSync";
            $result = $event |  where { ($_.ID -eq "5136" -and $_.message -match "AttributeLDAPDisplayName.*ntSecurityDescriptor" -and ($_.message -match "AttributeValue.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or $_.message -match "AttributeValue.*.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.message -match "AttributeValue.*.*89e95b76-444d-4c62-991a-0facbeda640c")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
