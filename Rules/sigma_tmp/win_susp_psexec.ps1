# Get-WinEvent -LogName Security | where {(($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and ($_.message -match "RelativeTargetName.*.*-stdin" -or $_.message -match "RelativeTargetName.*.*-stdout" -or $_.message -match "RelativeTargetName.*.*-stderr")) -and  -not ($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and $_.message -match "RelativeTargetName.*PSEXESVC.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_psexec";
    $detectedMessage = "detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and ($_.message -match "RelativeTargetName.*.*-stdin" -or $_.message -match "RelativeTargetName.*.*-stdout" -or $_.message -match "RelativeTargetName.*.*-stderr")) -and -not ($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and $_.message -match "RelativeTargetName.*PSEXESVC.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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