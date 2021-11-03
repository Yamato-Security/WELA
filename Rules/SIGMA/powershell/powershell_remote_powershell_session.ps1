# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4103" -and $_.message -match "HostName.*ServerRemoteHost" -and $_.message -match "HostApplication.*.*wsmprovhost.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Windows PowerShell | where {($_.ID -eq "400" -and $_.message -match "HostName.*ServerRemoteHost" -and $_.message -match "HostApplication.*.*wsmprovhost.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_remote_powershell_session";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "powershell_remote_powershell_session";
            $detectedMessage = "Detects remote PowerShell sessions";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event |  where { ($_.ID -eq "4103" -and $_.message -match "HostName.*ServerRemoteHost" -and $_.message -match "HostApplication.*.*wsmprovhost.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "400" -and $_.message -match "HostName.*ServerRemoteHost" -and $_.message -match "HostApplication.*.*wsmprovhost.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            if ($results.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
            }
            foreach ($result in $results) {
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
