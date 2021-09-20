# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "3" -and $_.message -match "Initiated.*true" -and ($_.message -match "DestinationHostname.*.*.github.com" -or $_.message -match "DestinationHostname.*.*.githubusercontent.com") -and $_.message -match "Image.*C:\Windows\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_win_binary_github_com";
    $detectedMessage = "Detects an executable in the Windows folder accessing github.com";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "3" -and $_.message -match "Initiated.*true" -and ($_.message -match "DestinationHostname.*.*.github.com" -or $_.message -match "DestinationHostname.*.*.githubusercontent.com") -and $_.message -match "Image.*C:\\Windows\\.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
