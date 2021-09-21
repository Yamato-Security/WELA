# Get-WinEvent | where {(($_.message -match "CommandLine.*.*echo .*" -or $_.message -match "CommandLine.*.*copy .*" -or $_.message -match "CommandLine.*.*type .*" -or $_.message -match "CommandLine.*.*file createnew.*") -and ($_.message -match "CommandLine.*.* C:\\Windows\\System32\\Tasks\\.*" -or $_.message -match "CommandLine.*.* C:\\Windows\\SysWow64\\Tasks\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_task_folder_evasion";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_task_folder_evasion";
            $detectedMessage = "The Tasks folder in system32 and syswow64 are globally writable paths. Adversaries can take advantage of this and load or influence any script hosts or ANY .NET Application in Tasks to load and execute a custom assembly into cscript, wscript, regsvr32, mshta, eventvwr";
            $result = $event |  where { (($_.message -match "CommandLine.*.*echo .*" -or $_.message -match "CommandLine.*.*copy .*" -or $_.message -match "CommandLine.*.*type .*" -or $_.message -match "CommandLine.*.*file createnew.*") -and ($_.message -match "CommandLine.*.* C:\\Windows\\System32\\Tasks\\.*" -or $_.message -match "CommandLine.*.* C:\\Windows\\SysWow64\\Tasks\\.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
