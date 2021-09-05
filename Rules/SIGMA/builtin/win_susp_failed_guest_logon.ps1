# Get-WinEvent -LogName Microsoft-Windows-SmbClient/Security | where {($_.ID -eq "31017" -and $_.message -match "Description.*.*Rejected an insecure guest logon.*" -and $_.message -match "UserName.*" -and $_.message -match "ServerName.*\1.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_failed_guest_logon";
    $detectedMessage = "Detect Attempt PrintNightmare (CVE-2021-1675) Remote code execution in Windows Spooler Service"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "31017" -and $_.message -match "Description.*.*Rejected an insecure guest logon.*" -and $_.message -match "UserName.*" -and $_.message -match "ServerName.*\1.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
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
