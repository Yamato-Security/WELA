# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "3") -and ($_.message -match "Image.*.*\powershell.exe" -and $_.message -match "Initiated.*true" -and $_.message -match "DestinationIsIpv6.*false") -and  -not (($_.message -match "DestinationIp.*10..*" -or $_.message -match "DestinationIp.*192.168..*" -or $_.message -match "DestinationIp.*172.16..*" -or $_.message -match "DestinationIp.*172.17..*" -or $_.message -match "DestinationIp.*172.18..*" -or $_.message -match "DestinationIp.*172.19..*" -or $_.message -match "DestinationIp.*172.20..*" -or $_.message -match "DestinationIp.*172.21..*" -or $_.message -match "DestinationIp.*172.22..*" -or $_.message -match "DestinationIp.*172.23..*" -or $_.message -match "DestinationIp.*172.24..*" -or $_.message -match "DestinationIp.*172.25..*" -or $_.message -match "DestinationIp.*172.26..*" -or $_.message -match "DestinationIp.*172.27..*" -or $_.message -match "DestinationIp.*172.28..*" -or $_.message -match "DestinationIp.*172.29..*" -or $_.message -match "DestinationIp.*172.30..*" -or $_.message -match "DestinationIp.*172.31..*" -or $_.message -match "DestinationIp.*127.0.0.1.*") -and $_.message -match "DestinationIsIpv6.*false" -and $_.message -match "User.*NT AUTHORITY\SYSTEM" -and $_.message -match "User.*.*AUT.*" -and $_.message -match "User.*.* NT.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_powershell_network_connection";
    $detectedMessage = "Detects a Powershell process that opens network connections - check for suspicious target ports and target systems - adjust to your environment (e.g."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "3") -and ($_.message -match "Image.*.*\powershell.exe" -and $_.message -match "Initiated.*true" -and $_.message -match "DestinationIsIpv6.*false") -and -not (($_.message -match "DestinationIp.*10..*" -or $_.message -match "DestinationIp.*192.168..*" -or $_.message -match "DestinationIp.*172.16..*" -or $_.message -match "DestinationIp.*172.17..*" -or $_.message -match "DestinationIp.*172.18..*" -or $_.message -match "DestinationIp.*172.19..*" -or $_.message -match "DestinationIp.*172.20..*" -or $_.message -match "DestinationIp.*172.21..*" -or $_.message -match "DestinationIp.*172.22..*" -or $_.message -match "DestinationIp.*172.23..*" -or $_.message -match "DestinationIp.*172.24..*" -or $_.message -match "DestinationIp.*172.25..*" -or $_.message -match "DestinationIp.*172.26..*" -or $_.message -match "DestinationIp.*172.27..*" -or $_.message -match "DestinationIp.*172.28..*" -or $_.message -match "DestinationIp.*172.29..*" -or $_.message -match "DestinationIp.*172.30..*" -or $_.message -match "DestinationIp.*172.31..*" -or $_.message -match "DestinationIp.*127.0.0.1.*") -and $_.message -match "DestinationIsIpv6.*false" -and $_.message -match "User.*NT AUTHORITY\SYSTEM" -and $_.message -match "User.*.*AUT.*" -and $_.message -match "User.*.* NT.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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