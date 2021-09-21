# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*new-object.*" -and $_.message -match "CommandLine.*.*net.webclient)..*" -and $_.message -match "CommandLine.*.*download.*" -and ($_.message -match "CommandLine.*.*string(.*" -or $_.message -match "CommandLine.*.*file(.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_powershell_download";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_powershell_download";
            $detectedMessage = "Detects a Powershell process that contains download commands in its command line string";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\powershell.exe" -and $_.message -match "CommandLine.*.*new-object.*" -and $_.message -match "CommandLine.*.*net.webclient)..*" -and $_.message -match "CommandLine.*.*download.*" -and ($_.message -match "CommandLine.*.*string(.*" -or $_.message -match "CommandLine.*.*file(.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
