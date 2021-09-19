# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\wscript.exe" -or $_.message -match "ParentImage.*.*\\cscript.exe") -and $_.message -match "Image.*.*\\powershell.exe") -and  -not ($_.message -match "CurrentDirectory.*.*\\Health Service State\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_powershell_parent_combo";
    $detectedMessage = "Detects suspicious powershell invocations from interpreters or unusual programs";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\wscript.exe" -or $_.message -match "ParentImage.*.*\\cscript.exe") -and $_.message -match "Image.*.*\\powershell.exe") -and -not ($_.message -match "CurrentDirectory.*.*\\Health Service State\\.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
