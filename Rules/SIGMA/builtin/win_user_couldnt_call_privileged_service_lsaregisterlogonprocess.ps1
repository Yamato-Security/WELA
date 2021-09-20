# Get-WinEvent -LogName Security | where {($_.ID -eq "4673" -and $_.message -match "Service.*LsaRegisterLogonProcess()" -and $_.message -match "Keywords.*0x8010000000000000") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_user_couldnt_call_privileged_service_lsaregisterlogonprocess";
    $detectedMessage = "The 'LsaRegisterLogonProcess' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege privilege set. Possible Rubeus tries to get a handle to LSA.";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4673" -and $_.message -match "Service.*LsaRegisterLogonProcess()" -and $_.message -match "Keywords.*0x8010000000000000") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
