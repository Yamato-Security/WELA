# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\\HarddiskVolumeShadowCopy.*" -and $_.message -match "CommandLine.*.*ystem32\\config\\sam.*" -and ($_.message -match "CommandLine.*.*Copy-Item.*" -or $_.message -match "CommandLine.*.*cp $_..*" -or $_.message -match "CommandLine.*.*cpi $_..*" -or $_.message -match "CommandLine.*.*copy $_..*" -or $_.message -match "CommandLine.*.*.File]::Copy(.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_powershell_sam_access";
    $detectedMessage = "Detects suspicious PowerShell scripts accessing SAM hives";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\\HarddiskVolumeShadowCopy.*" -and $_.message -match "CommandLine.*.*ystem32\\config\\sam.*" -and ($_.message -match "CommandLine.*.*Copy-Item.*" -or $_.message -match "CommandLine.*.*cp $_..*" -or $_.message -match "CommandLine.*.*cpi $_..*" -or $_.message -match "CommandLine.*.*copy $_..*" -or $_.message -match "CommandLine.*.*.File]::Copy(.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
