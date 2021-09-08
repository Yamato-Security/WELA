# Get-WinEvent -LogName Security | where {($_.ID -eq "4661" -and ($_.message -match "SAM_USER" -or $_.message -match "SAM_GROUP") -and $_.message -match "ObjectName.*S-1-5-21-.*" -and $_.message -match "AccessMask.*0x2d" -and ($_.message -match "ObjectName.*.*-500" -or $_.message -match "ObjectName.*.*-512")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_net_recon_activity";
    $detectedMessage = "Detects activity as ""net user administrator /domain"" and ""net group domain admins /domain""";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "4661" -and ($_.message -match "SAM_USER" -or $_.message -match "SAM_GROUP") -and $_.message -match "ObjectName.*S-1-5-21-.*" -and $_.message -match "AccessMask.*0x2d" -and ($_.message -match "ObjectName.*.*-500" -or $_.message -match "ObjectName.*.*-512")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
