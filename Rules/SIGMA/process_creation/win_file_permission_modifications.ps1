# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.message -match "Image.*.*\takeown.exe" -or $_.message -match "Image.*.*\cacls.exe" -or $_.message -match "Image.*.*\icacls.exe") -and $_.message -match "CommandLine.*.*/grant") -or ($_.message -match "Image.*.*\attrib.exe" -and $_.message -match "CommandLine.*.*-r"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_file_permission_modifications";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_file_permission_modifications";
            $detectedMessage = "Detects a file or folder's permissions being modified.";
            $result = $event | where { (($_.ID -eq "1") -and ((($_.message -match "Image.*.*\\takeown.exe" -or $_.message -match "Image.*.*\\cacls.exe" -or $_.message -match "Image.*.*\\icacls.exe") -and $_.message -match "CommandLine.*.*/grant") -or ($_.message -match "Image.*.*\\attrib.exe" -and $_.message -match "CommandLine.*.*-r"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
