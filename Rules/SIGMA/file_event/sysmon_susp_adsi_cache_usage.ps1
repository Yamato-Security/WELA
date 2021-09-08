# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*\Local\Microsoft\Windows\SchCache\.*" -and $_.message -match "TargetFilename.*.*.sch") -and  -not (($_.message -match "C:\windows\system32\svchost.exe" -or $_.message -match "C:\windows\system32\dllhost.exe" -or $_.message -match "C:\windows\system32\mmc.exe" -or $_.message -match "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe" -or $_.message -match "C:\Windows\CCM\CcmExec.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_susp_adsi_cache_usage";
    $detectedMessage = "Detects the usage of ADSI (LDAP) operations by tools. This may also detect tools like LDAPFragger.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*\Local\Microsoft\Windows\SchCache\.*" -and $_.message -match "TargetFilename.*.*.sch") -and -not (($_.message -match "C:\windows\system32\svchost.exe" -or $_.message -match "C:\windows\system32\dllhost.exe" -or $_.message -match "C:\windows\system32\mmc.exe" -or $_.message -match "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe" -or $_.message -match "C:\Windows\CCM\CcmExec.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
