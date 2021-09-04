# Get-WinEvent -LogName Security | where {(($_.ID -eq "4656" -or $_.ID -eq "4658" -or $_.ID -eq "4660" -or $_.ID -eq "4663") -and $_.message -match "ObjectName.*.*\wceaux.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_mal_wceaux_dll";
    $detectedMessage = "Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4656" -or $_.ID -eq "4658" -or $_.ID -eq "4660" -or $_.ID -eq "4663") -and $_.message -match "ObjectName.*.*\wceaux.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
