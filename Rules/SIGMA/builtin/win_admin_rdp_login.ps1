# Get-WinEvent -LogName Security | where {($_.ID -eq "4624" -and $_.message -match "LogonType.*10" -and $_.message -match "AuthenticationPackageName.*Negotiate" -and $_.message -match "TargetUserName.*Admin.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_admin_rdp_login";
    $detectedMessage = "Detect remote login by Administrator user (depending on internal pattern).";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_admin_rdp_login";
            $detectedMessage = "Detect remote login by Administrator user (depending on internal pattern).";
            $result = $event |  where { ($_.ID -eq "4624" -and $_.message -match "LogonType.*10" -and $_.message -match "AuthenticationPackageName.*Negotiate" -and $_.message -match "TargetUserName.*Admin.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
