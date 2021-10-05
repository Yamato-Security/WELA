# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\\calc.exe .*" -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\calc.exe" -and  -not ($_.message -match "Image.*.*\\Windows\\Sys.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_calc";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_calc";
            $detectedMessage = "Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\\calc.exe .*" -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\calc.exe" -and -not ($_.message -match "Image.*.*\\Windows\\Sys.*")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
