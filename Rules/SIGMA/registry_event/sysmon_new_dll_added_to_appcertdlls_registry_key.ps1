# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls" -or $_.message -match "NewName.*HKLM\\SYSTEM\\CurentControlSet\\Control\\Session Manager\\AppCertDlls")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_new_dll_added_to_appcertdlls_registry_key";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_new_dll_added_to_appcertdlls_registry_key";
            $detectedMessage = "Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key can be abused to obtain persistence and privilege escalation";
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls" -or $_.message -match "NewName.*HKLM\\SYSTEM\\CurentControlSet\\Control\\Session Manager\\AppCertDlls")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
