# Get-WinEvent -LogName Security | where {(($_.message -match "ObjectName.*.*WINEVT\Publishers\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" -or $_.message -match "ObjectName.*.*WINEVT\Channels\Microsoft-Windows-Sysmon/Operational") -and (($_.ID -eq "4657" -and $_.message -match "ObjectValueName.*Enabled" -and $_.message -match "NewValue.*0") -or ($_.ID -eq "4663" -and $_.message -match "AccessMask.*65536"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_sysmon_channel_reference_deletion";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_sysmon_channel_reference_deletion";
            $detectedMessage = "Potential threat actor tampering with Sysmon manifest and eventually disabling it";
            $result = $result | where { (($_.message -match "ObjectName.*.*WINEVT\\Publishers\\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" -or $_.message -match "ObjectName.*.*WINEVT\\Channels\\Microsoft-Windows-Sysmon/Operational") -and (($_.ID -eq "4657" -and $_.message -match "ObjectValueName.*Enabled" -and $_.message -match "NewValue.*0") -or ($_.ID -eq "4663" -and $_.message -match "AccessMask.*65536"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
