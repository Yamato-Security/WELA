# Get-WinEvent -LogName Security | where {($_.ID -eq "4663" -and $_.message -match "ObjectServer.*Security" -and $_.message -match "ObjectType.*File" -and $_.message -match "ObjectName.*\Device\CdRom.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_iso_mount";
    $detectedMessage = "Detects the mount of ISO images on an endpoint";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4663" -and $_.message -match "ObjectServer.*Security" -and $_.message -match "ObjectType.*File" -and $_.message -match "ObjectName.*\Device\CdRom.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
