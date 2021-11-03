# Get-WinEvent -LogName Security | where {($_.ID -eq "5136" -and $_.message -match "AttributeValue.*" -and ($_.message -match "primaryInternationalISDNNumber" -or $_.message -match "otherFacsimileTelephoneNumber" -or $_.message -match "primaryTelexNumber")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_ldap_dataexchange";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_ldap_dataexchange";
            $detectedMessage = "Detects the usage of particular AttributeLDAPDisplayNames, which are known for data exchange via LDAP by the tool LDAPFragger and are additionally not commonly used in companies.";
            $result = $event |  where { ($_.ID -eq "5136" -and $_.message -match "AttributeValue.*" -and ($_.message -match "primaryInternationalISDNNumber" -or $_.message -match "otherFacsimileTelephoneNumber" -or $_.message -match "primaryTelexNumber")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
