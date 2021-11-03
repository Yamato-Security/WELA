# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.ID -eq "4103" -and $_.message -match "ContextInfo.*") -and  -not ($_.message -match "ContextInfo.*powershell.exe" -or $_.message -match "Message.*powershell.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Windows PowerShell | where {(($_.ID -eq "400" -and $_.message -match "ContextInfo.*") -and  -not ($_.message -match "ContextInfo.*powershell.exe" -or $_.message -match "Message.*powershell.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message


function Add-Rule {

    $ruleName = "powershell_alternate_powershell_hosts";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_alternate_powershell_hosts";
            $detectedMessage = "Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event |  where { (($_.ID -eq "4103" -and $_.message -match "ContextInfo.*") -and -not ($_.message -match "ContextInfo.*powershell.exe" -or $_.message -match "Message.*powershell.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { (($_.ID -eq "400" -and $_.message -match "ContextInfo.*") -and -not ($_.message -match "ContextInfo.*powershell.exe" -or $_.message -match "Message.*powershell.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
