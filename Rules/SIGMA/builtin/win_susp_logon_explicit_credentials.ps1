# Get-WinEvent -LogName Security | where {(($_.ID -eq "4648" -and ($_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\pwsh.exe" -or $_.message -match "Image.*.*\winrs.exe" -or $_.message -match "Image.*.*\wmic.exe" -or $_.message -match "Image.*.*\net.exe" -or $_.message -match "Image.*.*\net1.exe" -or $_.message -match "Image.*.*\reg.exe")) -and  -not ($_.message -match "TargetServerName.*localhost")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_logon_explicit_credentials";
    $detectedMessage = "Detects suspicious processes logging on with explicit credentials";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "4648" -and ($_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\pwsh.exe" -or $_.message -match "Image.*.*\\winrs.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe" -or $_.message -match "Image.*.*\\reg.exe")) -and -not ($_.message -match "TargetServerName.*localhost")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
