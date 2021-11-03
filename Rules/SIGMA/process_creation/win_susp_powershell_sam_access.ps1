# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\\HarddiskVolumeShadowCopy" -and $_.message -match "CommandLine.*.*ystem32\\config\\sam" -and ($_.message -match "CommandLine.*.*Copy-Item" -or $_.message -match "CommandLine.*.*cp $_." -or $_.message -match "CommandLine.*.*cpi $_." -or $_.message -match "CommandLine.*.*copy $_." -or $_.message -match "CommandLine.*.*.File]::Copy(")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_powershell_sam_access";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_powershell_sam_access";
            $detectedMessage = "Detects suspicious PowerShell scripts accessing SAM hives";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*\\HarddiskVolumeShadowCopy" -and $_.message -match "CommandLine.*.*ystem32\\config\\sam" -and ($_.message -match "CommandLine.*.*Copy-Item" -or $_.message -match "CommandLine.*.*cp $_." -or $_.message -match "CommandLine.*.*cpi $_." -or $_.message -match "CommandLine.*.*copy $_." -or $_.message -match "CommandLine.*.*.File]::Copy(")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
