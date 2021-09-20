# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPt.*" -or $_.message -match "TargetObject.*.*\\CurrentControlSet\\Services\\NTDS\\LsaDbExtPt.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_lsass_dll_load";
    $detectedMessage = "Detects a method to load DLL via LSASS process using an undocumented Registry key";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "TargetObject.*.*\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPt.*" -or $_.message -match "TargetObject.*.*\\CurrentControlSet\\Services\\NTDS\\LsaDbExtPt.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
