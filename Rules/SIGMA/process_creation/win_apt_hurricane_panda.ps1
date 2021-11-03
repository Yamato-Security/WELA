# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*localgroup" -and $_.message -match "CommandLine.*.*admin" -and $_.message -match "CommandLine.*.*/add") -or ($_.message -match "CommandLine.*.*\Win64.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_hurricane_panda";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_hurricane_panda";
            $detectedMessage = "Detects Hurricane Panda Activity";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*localgroup" -and $_.message -match "CommandLine.*.*admin" -and $_.message -match "CommandLine.*.*/add") -or ($_.message -match "CommandLine.*.*\\Win64.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
