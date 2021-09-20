# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.ID -eq "1" -and ($_.message -match "Image.*.*\\bitsadmin.exe") -and ((($_.message -match "CommandLine.*.* /create .*" -or $_.message -match "CommandLine.*.* /addfile .*") -and ($_.message -match "CommandLine.*.*http.*")) -or ($_.message -match "CommandLine.*.* /transfer .*"))) -or ($_.message -match "CommandLine.*.*copy bitsadmin.exe.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_process_creation_bitsadmin_download";
    $detectedMessage = "Detects usage of bitsadmin downloading a file";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and (($_.ID -eq "1" -and ($_.message -match "Image.*.*\\bitsadmin.exe") -and ((($_.message -match "CommandLine.*.* /create .*" -or $_.message -match "CommandLine.*.* /addfile .*") -and ($_.message -match "CommandLine.*.*http.*")) -or ($_.message -match "CommandLine.*.* /transfer .*"))) -or ($_.message -match "CommandLine.*.*copy bitsadmin.exe.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
