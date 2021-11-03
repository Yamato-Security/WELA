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
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\svchost.exe" -and -not (($_.message -match "ParentImage.*.*\\services.exe" -or $_.message -match "ParentImage.*.*\\MsMpEng.exe" -or $_.message -match "ParentImage.*.*\\Mrt.exe" -or $_.message -match "ParentImage.*.*\\rpcnet.exe" -or $_.message -match "ParentImage.*.*\\svchost.exe"))) -and -not (-not $_.message -match "ParentImage")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
