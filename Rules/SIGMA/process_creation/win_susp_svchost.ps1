# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\\svchost.exe" -and  -not (($_.message -match "ParentImage.*.*\\services.exe" -or $_.message -match "ParentImage.*.*\\MsMpEng.exe" -or $_.message -match "ParentImage.*.*\\Mrt.exe" -or $_.message -match "ParentImage.*.*\\rpcnet.exe" -or $_.message -match "ParentImage.*.*\\svchost.exe"))) -and  -not (-not ParentImage="*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_svchost";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_svchost";
            $detectedMessage = "Detects a suspicious svchost process start";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\svchost.exe" -and -not (($_.message -match "ParentImage.*.*\\services.exe" -or $_.message -match "ParentImage.*.*\\MsMpEng.exe" -or $_.message -match "ParentImage.*.*\\Mrt.exe" -or $_.message -match "ParentImage.*.*\\rpcnet.exe" -or $_.message -match "ParentImage.*.*\\svchost.exe"))) -and -not (-not $_.message -match "ParentImage.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
