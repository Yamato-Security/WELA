# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*winzip.exe.*" -or $_.message -match "CommandLine.*.*winzip64.exe.*") -and ($_.message -match "CommandLine.*.*-s".*") -and ($_.message -match "CommandLine.*.* -min .*" -or $_.message -match "CommandLine.*.* -a .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_susp_winzip";
    $detectedMessage = "An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*winzip.exe.*" -or $_.message -match "CommandLine.*.*winzip64.exe.*") -and ($_.message -match "CommandLine.*.*-s.*") -and ($_.message -match "CommandLine.*.* -min .*" -or $_.message -match "CommandLine.*.* -a .*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
