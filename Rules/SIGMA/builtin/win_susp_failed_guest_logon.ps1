# Get-WinEvent -LogName Microsoft-Windows-SmbClient/Security | where {($_.ID -eq "31017" -and $_.message -match "Description.*.*Rejected an insecure guest logon" -and $_.message -match "UserName" -and $_.message -match "ServerName.*\1") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_failed_guest_logon";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_failed_guest_logon";
            $detectedMessage = "Detect Attempt PrintNightmare (CVE-2021-1675) Remote code execution in Windows Spooler Service";
            $result = $event |  where { ($_.ID -eq "31017" -and $_.message -match "Description.*.*Rejected an insecure guest logon" -and $_.message -match "UserName" -and $_.message -match "ServerName.*\\1") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
