# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "3") -and ($_.message -match "Image.*.*\svchost.exe" -and $_.message -match "Initiated.*true" -and $_.message -match "SourcePort.*3389") -and (($_.message -match "DestinationIp.*127..*") -or ($_.message -match "::1"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_rdp_reverse_tunnel";
    $detectedMessage = "Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "3") -and ($_.message -match "Image.*.*\svchost.exe" -and $_.message -match "Initiated.*true" -and $_.message -match "SourcePort.*3389") -and (($_.message -match "DestinationIp.*127..*") -or ($_.message -match "::1"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}