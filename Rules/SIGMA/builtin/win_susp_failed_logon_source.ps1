# Get-WinEvent -LogName Security | where {($_.ID -eq "4625" -and  -not ((($_.message -match "IpAddress.*.*-" -or ($_.message -match "IpAddress.*10." -or $_.message -match "IpAddress.*192.168." -or $_.message -match "IpAddress.*172.16." -or $_.message -match "IpAddress.*172.17." -or $_.message -match "IpAddress.*172.18." -or $_.message -match "IpAddress.*172.19." -or $_.message -match "IpAddress.*172.20." -or $_.message -match "IpAddress.*172.21." -or $_.message -match "IpAddress.*172.22." -or $_.message -match "IpAddress.*172.23." -or $_.message -match "IpAddress.*172.24." -or $_.message -match "IpAddress.*172.25." -or $_.message -match "IpAddress.*172.26." -or $_.message -match "IpAddress.*172.27." -or $_.message -match "IpAddress.*172.28." -or $_.message -match "IpAddress.*172.29." -or $_.message -match "IpAddress.*172.30." -or $_.message -match "IpAddress.*172.31." -or $_.message -match "IpAddress.*127." -or $_.message -match "IpAddress.*169.254.") -or $_.message -match "IpAddress.*::1" -or ($_.message -match "IpAddress.*fe80::" -or $_.message -match "IpAddress.*fc00::"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_failed_logon_source";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_failed_logon_source";
            $detectedMessage = "A login from a public IP can indicate a misconfigured firewall or network boundary.";
            $result = $event |  where { ($_.ID -eq "4625" -and -not ((($_.message -match "IpAddress.*.*-" -or ($_.message -match "IpAddress.*10." -or $_.message -match "IpAddress.*192.168." -or $_.message -match "IpAddress.*172.16." -or $_.message -match "IpAddress.*172.17." -or $_.message -match "IpAddress.*172.18." -or $_.message -match "IpAddress.*172.19." -or $_.message -match "IpAddress.*172.20." -or $_.message -match "IpAddress.*172.21." -or $_.message -match "IpAddress.*172.22." -or $_.message -match "IpAddress.*172.23." -or $_.message -match "IpAddress.*172.24." -or $_.message -match "IpAddress.*172.25." -or $_.message -match "IpAddress.*172.26." -or $_.message -match "IpAddress.*172.27." -or $_.message -match "IpAddress.*172.28." -or $_.message -match "IpAddress.*172.29." -or $_.message -match "IpAddress.*172.30." -or $_.message -match "IpAddress.*172.31." -or $_.message -match "IpAddress.*127." -or $_.message -match "IpAddress.*169.254.") -or $_.message -match "IpAddress.*::1" -or ($_.message -match "IpAddress.*fe80::" -or $_.message -match "IpAddress.*fc00::"))))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
