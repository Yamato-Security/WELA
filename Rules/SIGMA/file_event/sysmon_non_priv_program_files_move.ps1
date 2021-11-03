# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\Program Files\" -or $_.message -match "TargetFilename.*.*\Program Files (x86)\") -or ($_.message -match "TargetFilename.*\Windows\" -and  -not ($_.message -match "TargetFilename.*.*temp")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_non_priv_program_files_move";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_non_priv_program_files_move";
            $detectedMessage = "Search for dropping of files to Windows/Program Files fodlers by non-priviledged processes";
            $result = $event |  where { ($_.ID -eq "11" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "11") -and (($_.message -match "TargetFilename.*.*\\Program Files\\" -or $_.message -match "TargetFilename.*.*\\Program Files (x86)\\") -or ($_.message -match "TargetFilename.*\\Windows\\" -and -not ($_.message -match "TargetFilename.*.*temp")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
