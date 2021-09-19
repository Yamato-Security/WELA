# Get-WinEvent -LogName Security | where {($_.ID -eq "4656" -and $_.message -match "ObjectType.*Key" -and $_.message -match "ObjectName.*.*\SAM") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_sam_registry_hive_handle_request";
    $detectedMessage = "Detects handles requested to SAM registry hive";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4656" -and $_.message -match "ObjectType.*Key" -and $_.message -match "ObjectName.*.*\SAM") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
