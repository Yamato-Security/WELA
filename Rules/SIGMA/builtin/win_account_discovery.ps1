# Get-WinEvent -LogName Security | where {(($_.ID -eq "4661" -and ($_.message -match "SAM_USER" -or $_.message -match "SAM_GROUP")) -and (($_.message -match "ObjectName.*.*-512" -or $_.message -match "ObjectName.*.*-502" -or $_.message -match "ObjectName.*.*-500" -or $_.message -match "ObjectName.*.*-505" -or $_.message -match "ObjectName.*.*-519" -or $_.message -match "ObjectName.*.*-520" -or $_.message -match "ObjectName.*.*-544" -or $_.message -match "ObjectName.*.*-551" -or $_.message -match "ObjectName.*.*-555") -or ($_.message -match "ObjectName.*.*admin"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_account_discovery";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_account_discovery";
            $detectedMessage = "Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs";
            $result = $event |  where { (($_.ID -eq "4661" -and ($_.message -match "SAM_USER" -or $_.message -match "SAM_GROUP")) -and (($_.message -match "ObjectName.*.*-512" -or $_.message -match "ObjectName.*.*-502" -or $_.message -match "ObjectName.*.*-500" -or $_.message -match "ObjectName.*.*-505" -or $_.message -match "ObjectName.*.*-519" -or $_.message -match "ObjectName.*.*-520" -or $_.message -match "ObjectName.*.*-544" -or $_.message -match "ObjectName.*.*-551" -or $_.message -match "ObjectName.*.*-555") -or ($_.message -match "ObjectName.*.*admin"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
