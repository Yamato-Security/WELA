# Get-WinEvent -LogName Security | where {($_.ID -eq "4673" -and $_.message -match "Service.*LsaRegisterLogonProcess()" -and $_.message -match "Keywords.*0x8010000000000000") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_user_couldnt_call_privileged_service_lsaregisterlogonprocess";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_user_couldnt_call_privileged_service_lsaregisterlogonprocess";
            $detectedMessage = "The 'LsaRegisterLogonProcess' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege privilege set. Possible Rubeus tries to get a handle to LSA.";
            $result = $event |  where { ($_.ID -eq "4673" -and $_.message -match "Service.*LsaRegisterLogonProcess()" -and $_.message -match "Keywords.*0x8010000000000000") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
