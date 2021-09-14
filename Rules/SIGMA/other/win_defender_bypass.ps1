# Get-WinEvent -LogName Security | where {(($_.ID -eq "4657" -or $_.ID -eq "4656" -or $_.ID -eq "4660" -or $_.ID -eq "4663") -and $_.message -match "ObjectName.*.*\Microsoft\Windows Defender\Exclusions\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_defender_bypass";
    $detectedMessage = "'Detects scenarios where an windows defender exclusion was added in registry where an entity would want to bypass antivirus scanning from windows defender'";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4657" -or $_.ID -eq "4656" -or $_.ID -eq "4660" -or $_.ID -eq "4663") -and $_.message -match "ObjectName.*.*\Microsoft\Windows Defender\Exclusions\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
