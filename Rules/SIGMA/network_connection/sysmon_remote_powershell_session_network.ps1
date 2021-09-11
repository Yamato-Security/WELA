# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "3") -and ($_.message -match "5985" -or $_.message -match "5986") -and  -not ($_.message -match "User.*NT AUTHORITY\NETWORK SERVICE")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_remote_powershell_session_network";
    $detectedMessage = "Detects remote PowerShell connections by monitoring network outbound connections to ports 5985 or 5986 from a non-network service account.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "3") -and ($_.message -match "5985" -or $_.message -match "5986") -and -not ($_.message -match "User.*NT AUTHORITY\NETWORK SERVICE")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
