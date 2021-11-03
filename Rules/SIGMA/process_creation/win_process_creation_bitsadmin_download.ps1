# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.ID -eq "1" -and ($_.message -match "Image.*.*\\bitsadmin.exe") -and ((($_.message -match "CommandLine.*.* /create " -or $_.message -match "CommandLine.*.* /addfile ") -and ($_.message -match "CommandLine.*.*http")) -or ($_.message -match "CommandLine.*.* /transfer "))) -or ($_.message -match "CommandLine.*.*copy bitsadmin.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_process_creation_bitsadmin_download";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_process_creation_bitsadmin_download";
            $detectedMessage = "Detects usage of bitsadmin downloading a file";
            $result = $event | where { (($_.ID -eq "1") -and (($_.ID -eq "1" -and ($_.message -match "Image.*.*\\bitsadmin.exe") -and ((($_.message -match "CommandLine.*.* /create " -or $_.message -match "CommandLine.*.* /addfile ") -and ($_.message -match "CommandLine.*.*http")) -or ($_.message -match "CommandLine.*.* /transfer "))) -or ($_.message -match "CommandLine.*.*copy bitsadmin.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
