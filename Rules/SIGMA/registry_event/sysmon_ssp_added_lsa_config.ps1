# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages" -or $_.message -match "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages") -and  -not ($_.message -match "Image.*C:\\Windows\\system32\\msiexec.exe" -or $_.message -match "Image.*C:\\Windows\\syswow64\\MsiExec.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_ssp_added_lsa_config";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_ssp_added_lsa_config";
                    $detectedMessage = "Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows.";
                $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages" -or $_.message -match "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages") -and -not ($_.message -match "Image.*C:\\Windows\\system32\\msiexec.exe" -or $_.message -match "Image.*C:\\Windows\\syswow64\\MsiExec.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
