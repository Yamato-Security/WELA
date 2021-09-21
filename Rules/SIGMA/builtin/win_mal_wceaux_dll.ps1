# Get-WinEvent -LogName Security | where {(($_.ID -eq "4656" -or $_.ID -eq "4658" -or $_.ID -eq "4660" -or $_.ID -eq "4663") -and $_.message -match "ObjectName.*.*\wceaux.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_mal_wceaux_dll";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_mal_wceaux_dll";
            $detectedMessage = "Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host";
            $result = $event |  where { (($_.ID -eq "4656" -or $_.ID -eq "4658" -or $_.ID -eq "4660" -or $_.ID -eq "4663") -and $_.message -match "ObjectName.*.*\\wceaux.dll") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
