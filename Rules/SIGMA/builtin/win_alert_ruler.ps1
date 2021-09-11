# Get-WinEvent -LogName Security | where {(((($_.ID -eq "4776") -and $_.message -match "Workstation.*RULER") -or (($_.ID -eq "4624" -or $_.ID -eq "4625") -and $_.message -match "WorkstationName.*RULER"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_alert_ruler";
    $detectedMessage = "This events that are generated when using the hacktool Ruler by Sensepost";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(((($_.ID -eq "4776") -and $_.message -match "Workstation.*RULER") -or (($_.ID -eq "4624" -or $_.ID -eq "4625") -and $_.message -match "WorkstationName.*RULER"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
