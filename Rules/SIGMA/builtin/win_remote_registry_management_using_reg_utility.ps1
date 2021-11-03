# Get-WinEvent -LogName Security | where {(($_.ID -eq "5145" -and $_.message -match "RelativeTargetName.*.*\winreg") -and  -not ($_.message -match "IpAddress.*%Admins_Workstations%")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_remote_registry_management_using_reg_utility";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_remote_registry_management_using_reg_utility";
            $detectedMessage = "Remote registry management using REG utility from non-admin workstation";
            $result = $event |  where { (($_.ID -eq "5145" -and $_.message -match "RelativeTargetName.*.*\\winreg") -and -not ($_.message -match "IpAddress.*%Admins_Workstations%")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
