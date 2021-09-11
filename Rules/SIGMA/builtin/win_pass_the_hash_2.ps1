# Get-WinEvent -LogName Security | where {(($_.ID -eq "4624" -and (($_.message -match "SubjectUserSid.*S-1-0-0" -and $_.message -match "LogonType.*3" -and $_.message -match "LogonProcessName.*NtLmSsp" -and $_.message -match "KeyLength.*0") -or ($_.message -match "LogonType.*9" -and $_.message -match "LogonProcessName.*seclogo"))) -and  -not ($_.message -match "AccountName.*ANONYMOUS LOGON")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_pass_the_hash_2";
    $detectedMessage = "Detects the attack technique pass the hash which is used to move laterally inside the network";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "4624" -and (($_.message -match "SubjectUserSid.*S-1-0-0" -and $_.message -match "LogonType.*3" -and $_.message -match "LogonProcessName.*NtLmSsp" -and $_.message -match "KeyLength.*0") -or ($_.message -match "LogonType.*9" -and $_.message -match "LogonProcessName.*seclogo"))) -and -not ($_.message -match "AccountName.*ANONYMOUS LOGON")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
