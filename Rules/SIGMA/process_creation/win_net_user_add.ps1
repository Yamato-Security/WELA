# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\net.exe" -or $_.message -match "Image.*.*\net1.exe") -and $_.message -match "CommandLine.*.*user.*" -and $_.message -match "CommandLine.*.*add.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_net_user_add";
    $detectedMessage = "Identifies creation of local users via the net.exe command.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\net.exe" -or $_.message -match "Image.*.*\net1.exe") -and $_.message -match "CommandLine.*.*user.*" -and $_.message -match "CommandLine.*.*add.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
