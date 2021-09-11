# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\tshark.exe" -and $_.message -match "CommandLine.*.*-i.*") -or $_.message -match "Image.*.*\windump.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_network_sniffing";
    $detectedMessage = "Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\tshark.exe" -and $_.message -match "CommandLine.*.*-i.*") -or $_.message -match "Image.*.*\windump.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
