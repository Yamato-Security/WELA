# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "3") -and ($_.message -match "5985" -or $_.message -match "5986") -and  -not ($_.message -match "User.*NT AUTHORITY\NETWORK SERVICE")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_remote_powershell_session_network";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_remote_powershell_session_network";
            $detectedMessage = "Detects remote PowerShell connections by monitoring network outbound connections to ports 5985 or 5986 from a non-network service account.";
            $result = $event |  where { (($_.ID -eq "3") -and ($_.message -match "5985" -or $_.message -match "5986") -and -not ($_.message -match "User.*NT AUTHORITY\NETWORK SERVICE")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
