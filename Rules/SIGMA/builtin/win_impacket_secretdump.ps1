# Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\ADMIN$" -and $_.message -match "RelativeTargetName.*.*SYSTEM32\.*" -and $_.message -match "RelativeTargetName.*.*.tmp.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_impacket_secretdump";
    $detectedMessage = "Detect AD credential dumping using impacket secretdump HKTL";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\ADMIN$" -and $_.message -match "RelativeTargetName.*.*SYSTEM32\.*" -and $_.message -match "RelativeTargetName.*.*.tmp.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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