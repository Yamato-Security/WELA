# Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and ($_.message -match "RelativeTargetName.*.*\mimidrv.*" -or $_.message -match "RelativeTargetName.*.*\lsass.*" -or $_.message -match "RelativeTargetName.*.*\windows\minidump\.*" -or $_.message -match "RelativeTargetName.*.*\hiberfil.*" -or $_.message -match "RelativeTargetName.*.*\sqldmpr.*" -or $_.message -match "RelativeTargetName.*.*\sam.*" -or $_.message -match "RelativeTargetName.*.*\ntds.dit.*" -or $_.message -match "RelativeTargetName.*.*\security.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_transferring_files_with_credential_data_via_network_shares";
    $detectedMessage = "Transferring files with well-known filenames (sensitive files with credential data) using network shares"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "5145" -and ($_.message -match "RelativeTargetName.*.*\mimidrv.*" -or $_.message -match "RelativeTargetName.*.*\lsass.*" -or $_.message -match "RelativeTargetName.*.*\windows\minidump\.*" -or $_.message -match "RelativeTargetName.*.*\hiberfil.*" -or $_.message -match "RelativeTargetName.*.*\sqldmpr.*" -or $_.message -match "RelativeTargetName.*.*\sam.*" -or $_.message -match "RelativeTargetName.*.*\ntds.dit.*" -or $_.message -match "RelativeTargetName.*.*\security.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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