# Get-WinEvent -LogName Security | where {($_.ID -eq "4624" -and $_.message -match "LogonType.*9" -and $_.message -match "LogonProcessName.*seclogo" -and $_.message -match "AuthenticationPackageName.*Negotiate") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_overpass_the_hash";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_overpass_the_hash";
            $detectedMessage = "Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.";
            $result = $event |  where { ($_.ID -eq "4624" -and $_.message -match "LogonType.*9" -and $_.message -match "LogonProcessName.*seclogo" -and $_.message -match "AuthenticationPackageName.*Negotiate") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
