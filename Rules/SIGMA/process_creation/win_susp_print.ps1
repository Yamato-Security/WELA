# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\print.exe") -and ($_.message -match "CommandLine.*print.*") -and ($_.message -match "CommandLine.*.*/D.*") -and ($_.message -match "CommandLine.*.*.exe.*")) -and  -not (($_.message -match "CommandLine.*.*print.exe.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_print";
    $detectedMessage = "Attackers can use print.exe for remote file copy";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\print.exe") -and ($_.message -match "CommandLine.*print.*") -and ($_.message -match "CommandLine.*.*/D.*") -and ($_.message -match "CommandLine.*.*.exe.*")) -and -not (($_.message -match "CommandLine.*.*print.exe.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
