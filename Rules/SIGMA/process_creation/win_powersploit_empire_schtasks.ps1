# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\powershell.exe" -and $_.message -match "Image.*.*\\schtasks.exe" -and $_.message -match "CommandLine.*.*/Create" -and $_.message -match "CommandLine.*.*/SC" -and ($_.message -match "CommandLine.*.*ONLOGON" -or $_.message -match "CommandLine.*.*DAILY" -or $_.message -match "CommandLine.*.*ONIDLE" -or $_.message -match "CommandLine.*.*Updater") -and $_.message -match "CommandLine.*.*/TN" -and $_.message -match "CommandLine.*.*Updater" -and $_.message -match "CommandLine.*.*/TR" -and $_.message -match "CommandLine.*.*powershell") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_powersploit_empire_schtasks";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_powersploit_empire_schtasks";
            $detectedMessage = "Detects the creation of a schtask via PowerSploit or Empire Default Configuration.";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\powershell.exe" -and $_.message -match "Image.*.*\\schtasks.exe" -and $_.message -match "CommandLine.*.*/Create" -and $_.message -match "CommandLine.*.*/SC" -and ($_.message -match "CommandLine.*.*ONLOGON" -or $_.message -match "CommandLine.*.*DAILY" -or $_.message -match "CommandLine.*.*ONIDLE" -or $_.message -match "CommandLine.*.*Updater") -and $_.message -match "CommandLine.*.*/TN" -and $_.message -match "CommandLine.*.*Updater" -and $_.message -match "CommandLine.*.*/TR" -and $_.message -match "CommandLine.*.*powershell") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
