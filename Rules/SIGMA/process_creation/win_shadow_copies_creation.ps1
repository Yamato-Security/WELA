# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\vssadmin.exe") -and $_.message -match "CommandLine.*.*shadow.*" -and $_.message -match "CommandLine.*.*create.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_shadow_copies_creation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_shadow_copies_creation";
                    $detectedMessage = "Shadow Copies creation using operating systems utilities, possible credential access";
                $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\vssadmin.exe") -and $_.message -match "CommandLine.*.*shadow.*" -and $_.message -match "CommandLine.*.*create.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
