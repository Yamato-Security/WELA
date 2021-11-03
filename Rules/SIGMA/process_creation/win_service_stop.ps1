# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\sc.exe" -or $_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe") -and $_.message -match "CommandLine.*.*stop") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_service_stop";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_service_stop";
            $detectedMessage = "Detects a windows service to be stopped";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\sc.exe" -or $_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe") -and $_.message -match "CommandLine.*.*stop") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
