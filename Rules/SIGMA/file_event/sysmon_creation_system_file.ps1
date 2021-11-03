# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*\svchost.exe" -or $_.message -match "TargetFilename.*.*\rundll32.exe" -or $_.message -match "TargetFilename.*.*\services.exe" -or $_.message -match "TargetFilename.*.*\powershell.exe" -or $_.message -match "TargetFilename.*.*\regsvr32.exe" -or $_.message -match "TargetFilename.*.*\spoolsv.exe" -or $_.message -match "TargetFilename.*.*\lsass.exe" -or $_.message -match "TargetFilename.*.*\smss.exe" -or $_.message -match "TargetFilename.*.*\csrss.exe" -or $_.message -match "TargetFilename.*.*\conhost.exe" -or $_.message -match "TargetFilename.*.*\wininit.exe" -or $_.message -match "TargetFilename.*.*\lsm.exe" -or $_.message -match "TargetFilename.*.*\winlogon.exe" -or $_.message -match "TargetFilename.*.*\explorer.exe" -or $_.message -match "TargetFilename.*.*\taskhost.exe" -or $_.message -match "TargetFilename.*.*\Taskmgr.exe" -or $_.message -match "TargetFilename.*.*\taskmgr.exe" -or $_.message -match "TargetFilename.*.*\sihost.exe" -or $_.message -match "TargetFilename.*.*\RuntimeBroker.exe" -or $_.message -match "TargetFilename.*.*\runtimebroker.exe" -or $_.message -match "TargetFilename.*.*\smartscreen.exe" -or $_.message -match "TargetFilename.*.*\dllhost.exe" -or $_.message -match "TargetFilename.*.*\audiodg.exe" -or $_.message -match "TargetFilename.*.*\wlanext.exe") -and  -not (($_.message -match "TargetFilename.*C:\Windows\System32\" -or $_.message -match "TargetFilename.*C:\Windows\system32\" -or $_.message -match "TargetFilename.*C:\Windows\SysWow64\" -or $_.message -match "TargetFilename.*C:\Windows\SysWOW64\" -or $_.message -match "TargetFilename.*C:\Windows\winsxs\" -or $_.message -match "TargetFilename.*C:\Windows\WinSxS\" -or $_.message -match "TargetFilename.*\SystemRoot\System32\") -and ($_.message -match "Image.*.*\Windows\System32\dism.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_creation_system_file";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_creation_system_file";
            $detectedMessage = "Detects the creation of a executable with a system process name in a suspicious folder";
            $result = $event |  where { (($_.ID -eq "11") -and ($_.message -match "TargetFilename.*.*\\svchost.exe" -or $_.message -match "TargetFilename.*.*\\rundll32.exe" -or $_.message -match "TargetFilename.*.*\\services.exe" -or $_.message -match "TargetFilename.*.*\\powershell.exe" -or $_.message -match "TargetFilename.*.*\\regsvr32.exe" -or $_.message -match "TargetFilename.*.*\\spoolsv.exe" -or $_.message -match "TargetFilename.*.*\\lsass.exe" -or $_.message -match "TargetFilename.*.*\\smss.exe" -or $_.message -match "TargetFilename.*.*\\csrss.exe" -or $_.message -match "TargetFilename.*.*\\conhost.exe" -or $_.message -match "TargetFilename.*.*\\wininit.exe" -or $_.message -match "TargetFilename.*.*\\lsm.exe" -or $_.message -match "TargetFilename.*.*\\winlogon.exe" -or $_.message -match "TargetFilename.*.*\\explorer.exe" -or $_.message -match "TargetFilename.*.*\\taskhost.exe" -or $_.message -match "TargetFilename.*.*\\Taskmgr.exe" -or $_.message -match "TargetFilename.*.*\\taskmgr.exe" -or $_.message -match "TargetFilename.*.*\\sihost.exe" -or $_.message -match "TargetFilename.*.*\\RuntimeBroker.exe" -or $_.message -match "TargetFilename.*.*\\runtimebroker.exe" -or $_.message -match "TargetFilename.*.*\\smartscreen.exe" -or $_.message -match "TargetFilename.*.*\\dllhost.exe" -or $_.message -match "TargetFilename.*.*\\audiodg.exe" -or $_.message -match "TargetFilename.*.*\\wlanext.exe") -and -not (($_.message -match "TargetFilename.*C:\\Windows\\System32\\" -or $_.message -match "TargetFilename.*C:\\Windows\\system32\\" -or $_.message -match "TargetFilename.*C:\\Windows\\SysWow64\\" -or $_.message -match "TargetFilename.*C:\\Windows\\SysWOW64\\" -or $_.message -match "TargetFilename.*C:\\Windows\\winsxs\\" -or $_.message -match "TargetFilename.*C:\\Windows\\WinSxS\\" -or $_.message -match "TargetFilename.*\\SystemRoot\\System32\\") -and ($_.message -match "Image.*.*\\Windows\\System32\\dism.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
