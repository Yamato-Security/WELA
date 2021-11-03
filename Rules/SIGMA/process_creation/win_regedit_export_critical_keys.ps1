# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\regedit.exe" -and $_.message -match "CommandLine.*.* /E " -and ($_.message -match "CommandLine.*.*hklm" -or $_.message -match "CommandLine.*.*hkey_local_machine") -and ($_.message -match "CommandLine.*.*\\system" -or $_.message -match "CommandLine.*.*\\sam" -or $_.message -match "CommandLine.*.*\\security")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_regedit_export_critical_keys";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_regedit_export_critical_keys";
            $detectedMessage = "Detects the export of a crital Registry key to a file.";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\regedit.exe" -and $_.message -match "CommandLine.*.* /E " -and ($_.message -match "CommandLine.*.*hklm" -or $_.message -match "CommandLine.*.*hkey_local_machine") -and ($_.message -match "CommandLine.*.*\\system" -or $_.message -match "CommandLine.*.*\\sam" -or $_.message -match "CommandLine.*.*\\security")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
