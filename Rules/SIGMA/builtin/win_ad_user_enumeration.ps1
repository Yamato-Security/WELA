# Get-WinEvent -LogName Security | where {(($_.ID -eq "4662" -and ($_.message -match "ObjectType.*.*bf967aba-0de6-11d0-a285-00aa003049e2.*")) -and  -not ($_.message -match "SubjectUserName.*.*$" -or $_.message -match "SubjectUserName.*MSOL_.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_ad_user_enumeration";
    $detectedMessage = "Detects access to a domain user from a non-machine account";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "4662" -and ($_.message -match "ObjectType.*.*bf967aba-0de6-11d0-a285-00aa003049e2.*")) -and -not ($_.message -match "SubjectUserName.*.*$" -or $_.message -match "SubjectUserName.*MSOL_.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0]0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
