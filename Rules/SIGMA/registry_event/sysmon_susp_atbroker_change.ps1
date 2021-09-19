# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs.*" -or $_.message -match "TargetObject.*.*Software\Microsoft\Windows NT\CurrentVersion\Accessibility\Configuration.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_atbroker_change";
    $detectedMessage = "Detects creation/modification of Assisitive Technology applications and persistance with usage of ATs";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs.*" -or $_.message -match "TargetObject.*.*Software\Microsoft\Windows NT\CurrentVersion\Accessibility\Configuration.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
