# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*setup0.exe -p") -or ($_.message -match "CommandLine.*.*setup.exe" -and ($_.message -match "CommandLine.*.*-x:0" -or $_.message -match "CommandLine.*.*-x:1" -or $_.message -match "CommandLine.*.*-x:2")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_winnti_pipemon";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_winnti_pipemon";
            $detectedMessage = "Detects specific process characteristics of Winnti Pipemon malware reported by ESET";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*setup0.exe -p") -or ($_.message -match "CommandLine.*.*setup.exe" -and ($_.message -match "CommandLine.*.*-x:0" -or $_.message -match "CommandLine.*.*-x:1" -or $_.message -match "CommandLine.*.*-x:2")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
