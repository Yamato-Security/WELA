# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" -or $_.message -match "NewName.*HKLM\SYSTEM\CurentControlSet\Control\Session Manager\AppCertDlls")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_new_dll_added_to_appcertdlls_registry_key";
    $detectedMessage = "Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key can be abused to obtain persistence and privilege escalation"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" -or $_.message -match "NewName.*HKLM\SYSTEM\CurentControlSet\Control\Session Manager\AppCertDlls")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
