# Get-WinEvent -LogName Security | where {($_.ID -eq "4661" -and ($_.message -match "SAM_USER" -or $_.message -match "SAM_GROUP") -and $_.message -match "ObjectName.*S-1-5-21-" -and $_.message -match "AccessMask.*0x2d" -and ($_.message -match "ObjectName.*.*-500" -or $_.message -match "ObjectName.*.*-512")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_net_recon_activity";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_net_recon_activity";
            $detectedMessage = "Detects activity as ""net user administrator /domain"" and ""net group domain admins /domain""";
            $result = $event |  where { ($_.ID -eq "4661" -and ($_.message -match "SAM_USER" -or $_.message -match "SAM_GROUP") -and $_.message -match "ObjectName.*S-1-5-21-" -and $_.message -match "AccessMask.*0x2d" -and ($_.message -match "ObjectName.*.*-500" -or $_.message -match "ObjectName.*.*-512")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
