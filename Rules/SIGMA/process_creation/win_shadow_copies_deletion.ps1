# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*delete.*" -and ((($_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\wmic.exe" -or $_.message -match "Image.*.*\vssadmin.exe" -or $_.message -match "Image.*.*\diskshadow.exe") -and $_.message -match "CommandLine.*.*shadow.*") -or (($_.message -match "Image.*.*\wbadmin.exe") -and $_.message -match "CommandLine.*.*catalog.*" -and $_.message -match "CommandLine.*.*quiet.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_shadow_copies_deletion";
    $detectedMessage = "Shadow Copies deletion using operating systems utilities";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*delete.*" -and ((($_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\wmic.exe" -or $_.message -match "Image.*.*\vssadmin.exe" -or $_.message -match "Image.*.*\diskshadow.exe") -and $_.message -match "CommandLine.*.*shadow.*") -or (($_.message -match "Image.*.*\wbadmin.exe") -and $_.message -match "CommandLine.*.*catalog.*" -and $_.message -match "CommandLine.*.*quiet.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}