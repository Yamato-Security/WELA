# Get-WinEvent -LogName Windows PowerShell | where { ($_.ID -eq "400" -and ($_.message -match "HostApplication.*.*powercat .*" -or $_.message -match "HostApplication.*.*powercat.ps1.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.ID -eq "4103" -and ($_.message -match "ContextInfo.*.*powercat .*" -or $_.message -match "ContextInfo.*.*powercat.ps1.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "powershell_powercat";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "powershell_powercat";
            $detectedMessage = "Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network";
            $results = @()
            $results += $event | where { ($_.ID -eq "400" -and ($_.message -match "HostApplication.*.*powercat .*" -or $_.message -match "HostApplication.*.*powercat.ps1.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            $results += $event | where { ($_.ID -eq "4103" -and ($_.message -match "ContextInfo.*.*powercat .*" -or $_.message -match "ContextInfo.*.*powercat.ps1.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;
                    Write-Host $result;
                    Write-Host
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
