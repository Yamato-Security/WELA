# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*\Local\Microsoft\Windows\SchCache\" -and $_.message -match "TargetFilename.*.*.sch") -and  -not (($_.message -match "C:\windows\system32\svchost.exe" -or $_.message -match "C:\windows\system32\dllhost.exe" -or $_.message -match "C:\windows\system32\mmc.exe" -or $_.message -match "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe" -or $_.message -match "C:\Windows\CCM\CcmExec.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_adsi_cache_usage";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_adsi_cache_usage";
            $detectedMessage = "Detects the usage of ADSI (LDAP) operations by tools. This may also detect tools like LDAPFragger.";
            $result = $event |  where { (($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*\\Local\\Microsoft\\Windows\\SchCache\\" -and $_.message -match "TargetFilename.*.*.sch") -and -not (($_.message -match "C:\\windows\\system32\\svchost.exe" -or $_.message -match "C:\\windows\\system32\\dllhost.exe" -or $_.message -match "C:\\windows\\system32\\mmc.exe" -or $_.message -match "C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe" -or $_.message -match "C:\\Windows\\CCM\\CcmExec.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
