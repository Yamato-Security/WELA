# Get-WinEvent -LogName Security | where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and $_.message -match "RelativeTargetName.*spoolss") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_dce_rpc_smb_spoolss_named_pipe";
    $detectedMessage = "Detects the use of the spoolss named pipe over SMB. This can be used to trigger the authentication via NTLM of any machine that has the spoolservice enabled. "

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and $_.message -match "RelativeTargetName.*spoolss") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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