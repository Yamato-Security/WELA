# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication" -or $_.message -match "TargetObject.*.*\CurrentControlSet\Control\Terminal Server\fDenyTSConnections") -and $_.message -match "Details.*DWORD (0x00000000)") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_rdp_registry_modification";
    $detectedMessage = "Detects potential malicious modification of the property value of fDenyTSConnections and UserAuthentication to enable remote desktop connections.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication" -or $_.message -match "TargetObject.*.*\CurrentControlSet\Control\Terminal Server\fDenyTSConnections") -and $_.message -match "Details.*DWORD (0x00000000)") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
