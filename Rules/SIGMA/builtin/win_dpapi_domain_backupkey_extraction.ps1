# Get-WinEvent -LogName Security | where {($_.ID -eq "4662" -and $_.message -match "ObjectType.*SecretObject" -and $_.message -match "AccessMask.*0x2" -and $_.message -match "ObjectName.*BCKUPKEY") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_dpapi_domain_backupkey_extraction";
    $detectedMessage = "Detects tools extracting LSA secret DPAPI domain backup key from Domain Controllers";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4662" -and $_.message -match "ObjectType.*SecretObject" -and $_.message -match "AccessMask.*0x2" -and $_.message -match "ObjectName.*BCKUPKEY") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
