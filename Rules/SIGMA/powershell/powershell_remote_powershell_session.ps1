
function Add-Rule {

    $ruleName = "powershell_remote_powershell_session";
    $detectedMessage = "Detects remote PowerShell sessions";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4103" -and $_.message -match "HostName.*ServerRemoteHost" -and $_.message -match "HostApplication.*.*wsmprovhost.exe.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message Get-WinEvent -LogName Windows PowerShell | where {($_.ID -eq "400" -and $_.message -match "HostName.*ServerRemoteHost" -and $_.message -match "HostApplication.*.*wsmprovhost.exe.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
