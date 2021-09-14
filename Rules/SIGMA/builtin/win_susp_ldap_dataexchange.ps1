# Get-WinEvent -LogName Security | where {($_.ID -eq "5136" -and $_.message -match "AttributeValue.*.*" -and ($_.message -match "primaryInternationalISDNNumber" -or $_.message -match "otherFacsimileTelephoneNumber" -or $_.message -match "primaryTelexNumber")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_ldap_dataexchange";
    $detectedMessage = "Detects the usage of particular AttributeLDAPDisplayNames, which are known for data exchange via LDAP by the tool LDAPFragger and are additionally not commonly used in companies.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "5136" -and $_.message -match "AttributeValue.*.*" -and ($_.message -match "primaryInternationalISDNNumber" -or $_.message -match "otherFacsimileTelephoneNumber" -or $_.message -match "primaryTelexNumber")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
