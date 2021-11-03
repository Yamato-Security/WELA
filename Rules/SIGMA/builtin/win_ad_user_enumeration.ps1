# Get-WinEvent -LogName Security | where {(($_.ID -eq "4662" -and ($_.message -match "ObjectType.*.*bf967aba-0de6-11d0-a285-00aa003049e2")) -and  -not ($_.message -match "SubjectUserName.*.*$" -or $_.message -match "SubjectUserName.*MSOL_")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_ad_user_enumeration";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_ad_user_enumeration";
            $detectedMessage = "Detects access to a domain user from a non-machine account";
            $result = $event |  where { (($_.ID -eq "4662" -and ($_.message -match "ObjectType.*.*bf967aba-0de6-11d0-a285-00aa003049e2")) -and -not ($_.message -match "SubjectUserName.*.*$" -or $_.message -match "SubjectUserName.*MSOL_")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
