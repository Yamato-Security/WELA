# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*-noni.*" -and $_.message -match "CommandLine.*.*-ep.*" -and $_.message -match "CommandLine.*.*bypass.*" -and $_.message -match "CommandLine.*.*$.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_apt29_thinktanks";
    $detectedMessage = "This method detects a suspicious PowerShell command line combination as used by APT29 in a campaign against U.S. think tanks.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*-noni.*" -and $_.message -match "CommandLine.*.*-ep.*" -and $_.message -match "CommandLine.*.*bypass.*" -and $_.message -match "CommandLine.*.*$.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
