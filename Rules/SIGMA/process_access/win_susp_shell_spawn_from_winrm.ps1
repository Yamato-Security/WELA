# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\wsmprovhost.exe" -and ($_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\sh.exe" -or $_.message -match "Image.*.*\bash.exe" -or $_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\schtasks.exe" -or $_.message -match "Image.*.*\certutil.exe" -or $_.message -match "Image.*.*\whoami.exe" -or $_.message -match "Image.*.*\bitsadmin.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_shell_spawn_from_winrm";
    $detectedMessage = "Detects suspicious shell spawn from WinRM host process";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\wsmprovhost.exe" -and ($_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\sh.exe" -or $_.message -match "Image.*.*\\bash.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\schtasks.exe" -or $_.message -match "Image.*.*\\certutil.exe" -or $_.message -match "Image.*.*\\whoami.exe" -or $_.message -match "Image.*.*\\bitsadmin.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
