# Get-WinEvent -LogName Security | where {(($_.ID -eq "5145" -and $_.message -match "RelativeTargetName.*.*\winreg.*") -and  -not ($_.message -match "IpAddress.*%Admins_Workstations%")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_remote_registry_management_using_reg_utility";
    $detectedMessage = "Remote registry management using REG utility from non-admin workstation";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "5145" -and $_.message -match "RelativeTargetName.*.*\\winreg.*") -and -not ($_.message -match "IpAddress.*%Admins_Workstations%")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
