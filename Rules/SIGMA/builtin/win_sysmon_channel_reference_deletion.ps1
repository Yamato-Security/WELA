# Get-WinEvent -LogName Security | where {(($_.message -match "ObjectName.*.*WINEVT\Publishers\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}.*" -or $_.message -match "ObjectName.*.*WINEVT\Channels\Microsoft-Windows-Sysmon/Operational.*") -and (($_.ID -eq "4657" -and $_.message -match "ObjectValueName.*Enabled" -and $_.message -match "NewValue.*0") -or ($_.ID -eq "4663" -and $_.message -match "AccessMask.*65536"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_sysmon_channel_reference_deletion";
    $detectedMessage = "Potential threat actor tampering with Sysmon manifest and eventually disabling it";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $result | where { (($_.message -match "ObjectName.*.*WINEVT\Publishers\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}.*" -or $_.message -match "ObjectName.*.*WINEVT\Channels\Microsoft-Windows-Sysmon/Operational.*") -and (($_.ID -eq "4657" -and $_.message -match "ObjectValueName.*Enabled" -and $_.message -match "NewValue.*0") -or ($_.ID -eq "4663" -and $_.message -match "AccessMask.*65536"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
