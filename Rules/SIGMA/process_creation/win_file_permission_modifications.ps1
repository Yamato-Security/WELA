# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.message -match "Image.*.*\takeown.exe" -or $_.message -match "Image.*.*\cacls.exe" -or $_.message -match "Image.*.*\icacls.exe") -and $_.message -match "CommandLine.*.*/grant.*") -or ($_.message -match "Image.*.*\attrib.exe" -and $_.message -match "CommandLine.*.*-r.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_file_permission_modifications";
    $detectedMessage = "Detects a file or folder's permissions being modified.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and ((($_.message -match "Image.*.*\takeown.exe" -or $_.message -match "Image.*.*\cacls.exe" -or $_.message -match "Image.*.*\icacls.exe") -and $_.message -match "CommandLine.*.*/grant.*") -or ($_.message -match "Image.*.*\attrib.exe" -and $_.message -match "CommandLine.*.*-r.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
