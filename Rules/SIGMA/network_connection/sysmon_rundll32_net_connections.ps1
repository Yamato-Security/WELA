# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "3") -and ($_.message -match "Image.*.*\rundll32.exe" -and $_.message -match "Initiated.*true") -and  -not (($_.message -match "DestinationIp.*10." -or $_.message -match "DestinationIp.*192.168." -or $_.message -match "DestinationIp.*172.16." -or $_.message -match "DestinationIp.*172.17." -or $_.message -match "DestinationIp.*172.18." -or $_.message -match "DestinationIp.*172.19." -or $_.message -match "DestinationIp.*172.20." -or $_.message -match "DestinationIp.*172.21." -or $_.message -match "DestinationIp.*172.22." -or $_.message -match "DestinationIp.*172.23." -or $_.message -match "DestinationIp.*172.24." -or $_.message -match "DestinationIp.*172.25." -or $_.message -match "DestinationIp.*172.26." -or $_.message -match "DestinationIp.*172.27." -or $_.message -match "DestinationIp.*172.28." -or $_.message -match "DestinationIp.*172.29." -or $_.message -match "DestinationIp.*172.30." -or $_.message -match "DestinationIp.*172.31." -or $_.message -match "DestinationIp.*127."))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_rundll32_net_connections";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_rundll32_net_connections";
            $detectedMessage = "Detects a rundll32 that communicates with public IP addresses";
            $result = $event |  where { (($_.ID -eq "3") -and ($_.message -match "Image.*.*\\rundll32.exe" -and $_.message -match "Initiated.*true") -and -not (($_.message -match "DestinationIp.*10." -or $_.message -match "DestinationIp.*192.168." -or $_.message -match "DestinationIp.*172.16." -or $_.message -match "DestinationIp.*172.17." -or $_.message -match "DestinationIp.*172.18." -or $_.message -match "DestinationIp.*172.19." -or $_.message -match "DestinationIp.*172.20." -or $_.message -match "DestinationIp.*172.21." -or $_.message -match "DestinationIp.*172.22." -or $_.message -match "DestinationIp.*172.23." -or $_.message -match "DestinationIp.*172.24." -or $_.message -match "DestinationIp.*172.25." -or $_.message -match "DestinationIp.*172.26." -or $_.message -match "DestinationIp.*172.27." -or $_.message -match "DestinationIp.*172.28." -or $_.message -match "DestinationIp.*172.29." -or $_.message -match "DestinationIp.*172.30." -or $_.message -match "DestinationIp.*172.31." -or $_.message -match "DestinationIp.*127."))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
