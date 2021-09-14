# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*7z.exe.*" -or $_.message -match "CommandLine.*.*7za.exe.*") -and $_.message -match "CommandLine.*.* -p.*" -and ($_.message -match "CommandLine.*.* a .*" -or $_.message -match "CommandLine.*.* u .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_susp_7z";
    $detectedMessage = "An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*7z.exe.*" -or $_.message -match "CommandLine.*.*7za.exe.*") -and $_.message -match "CommandLine.*.* -p.*" -and ($_.message -match "CommandLine.*.* a .*" -or $_.message -match "CommandLine.*.* u .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
