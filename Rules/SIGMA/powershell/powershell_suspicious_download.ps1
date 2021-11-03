# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.message -match "System.Net.WebClient" -and ($_.message -match ".DownloadFile(" -or $_.message -match ".DownloadString(")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Windows PowerShell | where {($_.ID -eq "400" -and $_.message -match "HostApplication.*.*System.Net.WebClient" -and ($_.message -match "HostApplication.*.*.DownloadFile(" -or $_.message -match "HostApplication.*.*.DownloadString(")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message


function Add-Rule {

    $ruleName = "powershell_suspicious_download";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "powershell_suspicious_download";
            $detectedMessage = "Detects suspicious PowerShell download command";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event |  where { ($_.message -match "System.Net.WebClient" -and ($_.message -match ".DownloadFile\(" -or $_.message -match ".DownloadString\(")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "400" -and $_.message -match "HostApplication.*.*System.Net.WebClient" -and ($_.message -match "HostApplication.*.*.DownloadFile\(" -or $_.message -match "HostApplication.*.*.DownloadString\(")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            
            if ($result -and $result.Count -ne 0) {
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
