# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.message -match ".*System.Net.WebClient.*" -and ($_.message -match ".*.DownloadFile(.*" -or $_.message -match ".*.DownloadString(.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Windows PowerShell | where {($_.ID -eq "400" -and $_.message -match "HostApplication.*.*System.Net.WebClient.*" -and ($_.message -match "HostApplication.*.*.DownloadFile(.*" -or $_.message -match "HostApplication.*.*.DownloadString(.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message


function Add-Rule {

    $ruleName = "powershell_suspicious_download";
    $detectedMessage = "Detects suspicious PowerShell download command";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event |  where { ($_.message -match ".*System.Net.WebClient.*" -and ($_.message -match ".*.DownloadFile(.*" -or $_.message -match ".*.DownloadString(.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            $results += $event | where { ($_.ID -eq "400" -and $_.message -match "HostApplication.*.*System.Net.WebClient.*" -and ($_.message -match "HostApplication.*.*.DownloadFile(.*" -or $_.message -match "HostApplication.*.*.DownloadString(.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
            }
            foreach ($result in $results) {
                Write-Host $result;
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
