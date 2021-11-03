# Get-WinEvent -LogName Windows PowerShell | where { ($_.ID -eq "400" -and ($_.message -match "HostApplication.*.*powercat " -or $_.message -match "HostApplication.*.*powercat.ps1")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.ID -eq "4103" -and ($_.message -match "ContextInfo.*.*powercat " -or $_.message -match "ContextInfo.*.*powercat.ps1")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "powershell_powercat";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "powershell_powercat";
            $detectedMessage = "Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network";
            $results = [System.Collections.ArrayList] @()
            $tmp = $event | where { ($_.ID -eq "400" -and ($_.message -match "HostApplication.*.*powercat " -or $_.message -match "HostApplication.*.*powercat.ps1")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "4103" -and ($_.message -match "ContextInfo.*.*powercat " -or $_.message -match "ContextInfo.*.*powercat.ps1")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;
                    Write-Output $result;
                    Write-Output ""; 
                }
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
