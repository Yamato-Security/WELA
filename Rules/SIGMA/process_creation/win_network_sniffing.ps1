# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\tshark.exe" -and $_.message -match "CommandLine.*.*-i") -or $_.message -match "Image.*.*\windump.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_network_sniffing";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_network_sniffing";
            $detectedMessage = "Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\tshark.exe" -and $_.message -match "CommandLine.*.*-i") -or $_.message -match "Image.*.*\\windump.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
