# Get-WinEvent -LogName Security | where {(((((($_.ID -eq "4738" -and  -not ($_.message -match "AllowedToDelegateTo.*-")) -and  -not (-not AllowedToDelegateTo="*")) -or ($_.ID -eq "5136" -and $_.message -match "AttributeLDAPDisplayName.*msDS-AllowedToDelegateTo")) -or ($_.ID -eq "5136" -and $_.message -match "ObjectClass.*user" -and $_.message -match "AttributeLDAPDisplayName.*servicePrincipalName")) -or ($_.ID -eq "5136" -and $_.message -match "AttributeLDAPDisplayName.*msDS-AllowedToActOnBehalfOfOtherIdentity"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_alert_ad_user_backdoors";
    $detectedMessage = "Detects scenarios where one can control another users or computers account without having to use their credentials.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (((((($_.ID -eq "4738" -and -not ($_.message -match "AllowedToDelegateTo.*-")) ) -or ($_.ID -eq "5136" -and $_.message -match "AttributeLDAPDisplayName.*msDS-AllowedToDelegateTo")) -or ($_.ID -eq "5136" -and $_.message -match "ObjectClass.*user" -and $_.message -match "AttributeLDAPDisplayName.*servicePrincipalName")) -or ($_.ID -eq "5136" -and $_.message -match "AttributeLDAPDisplayName.*msDS-AllowedToActOnBehalfOfOtherIdentity"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
