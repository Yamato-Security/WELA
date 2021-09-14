# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\esentutl.exe" -and ($_.message -match "CommandLine.*.*vss.*" -or $_.message -match "CommandLine.*.* /m .*" -or $_.message -match "CommandLine.*.* /y .*")) -or ($_.message -match "CommandLine.*.*\windows\ntds\ntds.dit.*" -or $_.message -match "CommandLine.*.*\config\sam.*" -or $_.message -match "CommandLine.*.*\config\security.*" -or $_.message -match "CommandLine.*.*\config\system .*" -or $_.message -match "CommandLine.*.*\repair\sam.*" -or $_.message -match "CommandLine.*.*\repair\system.*" -or $_.message -match "CommandLine.*.*\repair\security.*" -or $_.message -match "CommandLine.*.*\config\RegBack\sam.*" -or $_.message -match "CommandLine.*.*\config\RegBack\system.*" -or $_.message -match "CommandLine.*.*\config\RegBack\security.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_copying_sensitive_files_with_credential_data";
    $detectedMessage = "Files with well-known filenames (sensitive files with credential data) copying";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\esentutl.exe" -and ($_.message -match "CommandLine.*.*vss.*" -or $_.message -match "CommandLine.*.* /m .*" -or $_.message -match "CommandLine.*.* /y .*")) -or ($_.message -match "CommandLine.*.*\windows\ntds\ntds.dit.*" -or $_.message -match "CommandLine.*.*\config\sam.*" -or $_.message -match "CommandLine.*.*\config\security.*" -or $_.message -match "CommandLine.*.*\config\system .*" -or $_.message -match "CommandLine.*.*\repair\sam.*" -or $_.message -match "CommandLine.*.*\repair\system.*" -or $_.message -match "CommandLine.*.*\repair\security.*" -or $_.message -match "CommandLine.*.*\config\RegBack\sam.*" -or $_.message -match "CommandLine.*.*\config\RegBack\system.*" -or $_.message -match "CommandLine.*.*\config\RegBack\security.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
