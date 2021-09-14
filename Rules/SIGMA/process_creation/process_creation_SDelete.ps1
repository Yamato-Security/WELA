# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "OriginalFileName.*sdelete.exe" -and  -not (($_.message -match "CommandLine.*.* -h.*" -or $_.message -match "CommandLine.*.* -c.*" -or $_.message -match "CommandLine.*.* -z.*" -or $_.message -match "CommandLine.*.* /?.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_SDelete";
    $detectedMessage = "Use of SDelete to erase a file not the free space";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | !firstpipe!
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
