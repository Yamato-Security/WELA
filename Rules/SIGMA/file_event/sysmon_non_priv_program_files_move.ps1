# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\Program Files\.*" -or $_.message -match "TargetFilename.*.*\Program Files (x86)\.*") -or ($_.message -match "TargetFilename.*\Windows\.*" -and  -not ($_.message -match "TargetFilename.*.*temp.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_non_priv_program_files_move";
    $detectedMessage = "Search for dropping of files to Windows/Program Files fodlers by non-priviledged processes";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "11" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\Program Files\.*" -or $_.message -match "TargetFilename.*.*\Program Files (x86)\.*") -or ($_.message -match "TargetFilename.*\Windows\.*" -and -not ($_.message -match "TargetFilename.*.*temp.*")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
