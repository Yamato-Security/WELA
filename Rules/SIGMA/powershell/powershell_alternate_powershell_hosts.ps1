# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.ID -eq "4103" -and $_.message -match "ContextInfo.*.*") -and  -not ($_.message -match "ContextInfo.*powershell.exe" -or $_.message -match "Message.*powershell.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Windows PowerShell | where {(($_.ID -eq "400" -and $_.message -match "ContextInfo.*.*") -and  -not ($_.message -match "ContextInfo.*powershell.exe" -or $_.message -match "Message.*powershell.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message


function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "powershell_alternate_powershell_hosts";
    $detectedMessage = "Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "4103" -and $_.message -match "ContextInfo.*.*") -and -not ($_.message -match "ContextInfo.*powershell.exe" -or $_.message -match "Message.*powershell.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message; $result2 = $event | where { (($_.ID -eq "400" -and $_.message -match "ContextInfo.*.*") -and -not ($_.message -match "ContextInfo.*powershell.exe" -or $_.message -match "Message.*powershell.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if (($result.Count -ne 0) -or ($result2.Count -ne 0)) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
