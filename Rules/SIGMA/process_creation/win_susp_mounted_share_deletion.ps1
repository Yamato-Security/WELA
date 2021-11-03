# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\net.exe" -and $_.message -match "Image.*.*\\net1.exe" -and $_.message -match "CommandLine.*.*share" -and $_.message -match "CommandLine.*.*/delete") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_mounted_share_deletion";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_mounted_share_deletion";
            $detectedMessage = "Detects when when a mounted share is removed. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\net.exe" -and $_.message -match "Image.*.*\\net1.exe" -and $_.message -match "CommandLine.*.*share" -and $_.message -match "CommandLine.*.*/delete") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
