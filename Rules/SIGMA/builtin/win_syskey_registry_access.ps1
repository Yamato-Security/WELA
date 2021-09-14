# Get-WinEvent -LogName Security | where {(($_.ID -eq "4656" -or $_.ID -eq "4663") -and $_.message -match "ObjectType.*key" -and ($_.message -match "ObjectName.*.*lsa\JD" -or $_.message -match "ObjectName.*.*lsa\GBG" -or $_.message -match "ObjectName.*.*lsa\Skew1" -or $_.message -match "ObjectName.*.*lsa\Data")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_syskey_registry_access";
    $detectedMessage = "Detects handle requests and access operations to specific registry keys to calculate the SysKey";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4656" -or $_.ID -eq "4663") -and $_.message -match "ObjectType.*key" -and ($_.message -match "ObjectName.*.*lsa\JD" -or $_.message -match "ObjectName.*.*lsa\GBG" -or $_.message -match "ObjectName.*.*lsa\Skew1" -or $_.message -match "ObjectName.*.*lsa\Data")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
