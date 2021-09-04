# Get-WinEvent -LogName Security | where {(($_.ID -eq "4661" -and ($_.message -match "SAM_USER" -or $_.message -match "SAM_GROUP")) -and (($_.message -match "ObjectName.*.*-512" -or $_.message -match "ObjectName.*.*-502" -or $_.message -match "ObjectName.*.*-500" -or $_.message -match "ObjectName.*.*-505" -or $_.message -match "ObjectName.*.*-519" -or $_.message -match "ObjectName.*.*-520" -or $_.message -match "ObjectName.*.*-544" -or $_.message -match "ObjectName.*.*-551" -or $_.message -match "ObjectName.*.*-555") -or ($_.message -match "ObjectName.*.*admin.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_account_discovery";
    $detectedMessage = "Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4661" -and ($_.message -match "SAM_USER" -or $_.message -match "SAM_GROUP")) -and (($_.message -match "ObjectName.*.*-512" -or $_.message -match "ObjectName.*.*-502" -or $_.message -match "ObjectName.*.*-500" -or $_.message -match "ObjectName.*.*-505" -or $_.message -match "ObjectName.*.*-519" -or $_.message -match "ObjectName.*.*-520" -or $_.message -match "ObjectName.*.*-544" -or $_.message -match "ObjectName.*.*-551" -or $_.message -match "ObjectName.*.*-555") -or ($_.message -match "ObjectName.*.*admin.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
