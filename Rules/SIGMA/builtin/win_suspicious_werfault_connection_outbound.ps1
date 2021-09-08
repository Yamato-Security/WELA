# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "3") -and $_.message -match "Image.*werfault.exe" -and  -not (($_.ID -eq "3" -and $_.message -match "ParentImage.*svchost.exe" -and ($_.message -match "104.42.151.234" -or $_.message -match "104.43.193.48" -or $_.message -match "52.255.188.83" -or $_.message -match "13.64.90.137" -or $_.message -match "168.61.161.212" -or $_.message -match "13.88.21.125" -or $_.message -match "40.88.32.150" -or $_.message -match "52.147.198.201" -or $_.message -match "52.239.207.100" -or $_.message -match "52.176.224.96" -or $_.message -match "2607:7700:0:24:0:1:287e:1894" -or $_.message -match "DestinationIp.*10..*" -or $_.message -match "DestinationIp.*192.168..*" -or $_.message -match "DestinationIp.*127..*") -and ($_.message -match "DestinationHostname.*.*.windowsupdate.com.*" -or $_.message -match "DestinationHostname.*.*.microsoft.com.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_suspicious_werfault_connection_outbound";
    $detectedMessage = "Adversaries can migrate cobalt strike/metasploit/C2 beacons on compromised systems to legitimate werfault.exe process to avoid detection.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "3") -and $_.message -match "Image.*werfault.exe" -and -not (($_.ID -eq "3" -and $_.message -match "ParentImage.*svchost.exe" -and ($_.message -match "104.42.151.234" -or $_.message -match "104.43.193.48" -or $_.message -match "52.255.188.83" -or $_.message -match "13.64.90.137" -or $_.message -match "168.61.161.212" -or $_.message -match "13.88.21.125" -or $_.message -match "40.88.32.150" -or $_.message -match "52.147.198.201" -or $_.message -match "52.239.207.100" -or $_.message -match "52.176.224.96" -or $_.message -match "2607:7700:0:24:0:1:287e:1894" -or $_.message -match "DestinationIp.*10..*" -or $_.message -match "DestinationIp.*192.168..*" -or $_.message -match "DestinationIp.*127..*") -and ($_.message -match "DestinationHostname.*.*.windowsupdate.com.*" -or $_.message -match "DestinationHostname.*.*.microsoft.com.*")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
