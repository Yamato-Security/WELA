# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4103" -and $_.message -match "HostName.*ServerRemoteHost" -and $_.message -match "HostApplication.*.*wsmprovhost.exe.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Windows PowerShell | where {($_.ID -eq "400" -and $_.message -match "HostName.*ServerRemoteHost" -and $_.message -match "HostApplication.*.*wsmprovhost.exe.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_remote_powershell_session";
    $detectedMessage = "Detects remote PowerShell sessions";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event |  where { ($_.ID -eq "4103" -and $_.message -match "HostName.*ServerRemoteHost" -and $_.message -match "HostApplication.*.*wsmprovhost.exe.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            $results += $event | where { ($_.ID -eq "400" -and $_.message -match "HostName.*ServerRemoteHost" -and $_.message -match "HostApplication.*.*wsmprovhost.exe.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($results.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $detectedMessage;
            }
            foreach ($result in $results) {
                Write-Host $result;
            }
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
