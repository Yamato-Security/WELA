# Get-WinEvent -LogName Security | where {($_.ID -eq "4662" -and $_.message -match "ObjectType.*SecretObject" -and $_.message -match "AccessMask.*0x2" -and $_.message -match "ObjectName.*BCKUPKEY") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_dpapi_domain_backupkey_extraction";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_dpapi_domain_backupkey_extraction";
            $detectedMessage = "Detects tools extracting LSA secret DPAPI domain backup key from Domain Controllers";
            $result = $event |  where { ($_.ID -eq "4662" -and $_.message -match "ObjectType.*SecretObject" -and $_.message -match "AccessMask.*0x2" -and $_.message -match "ObjectName.*BCKUPKEY") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
