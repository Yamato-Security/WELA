# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\powershell.exe" -and $_.message -match "Image.*.*\schtasks.exe" -and $_.message -match "CommandLine.*.*/Create.*" -and $_.message -match "CommandLine.*.*/SC.*" -and ($_.message -match "CommandLine.*.*ONLOGON.*" -or $_.message -match "CommandLine.*.*DAILY.*" -or $_.message -match "CommandLine.*.*ONIDLE.*" -or $_.message -match "CommandLine.*.*Updater.*") -and $_.message -match "CommandLine.*.*/TN.*" -and $_.message -match "CommandLine.*.*Updater.*" -and $_.message -match "CommandLine.*.*/TR.*" -and $_.message -match "CommandLine.*.*powershell.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_powersploit_empire_schtasks";
    $detectedMessage = "Detects the creation of a schtask via PowerSploit or Empire Default Configuration.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\powershell.exe" -and $_.message -match "Image.*.*\schtasks.exe" -and $_.message -match "CommandLine.*.*/Create.*" -and $_.message -match "CommandLine.*.*/SC.*" -and ($_.message -match "CommandLine.*.*ONLOGON.*" -or $_.message -match "CommandLine.*.*DAILY.*" -or $_.message -match "CommandLine.*.*ONIDLE.*" -or $_.message -match "CommandLine.*.*Updater.*") -and $_.message -match "CommandLine.*.*/TN.*" -and $_.message -match "CommandLine.*.*Updater.*" -and $_.message -match "CommandLine.*.*/TR.*" -and $_.message -match "CommandLine.*.*powershell.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
