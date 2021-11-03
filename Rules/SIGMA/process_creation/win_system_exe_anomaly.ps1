# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\\svchost.exe" -or $_.message -match "Image.*.*\\rundll32.exe" -or $_.message -match "Image.*.*\\services.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\regsvr32.exe" -or $_.message -match "Image.*.*\\spoolsv.exe" -or $_.message -match "Image.*.*\\lsass.exe" -or $_.message -match "Image.*.*\\smss.exe" -or $_.message -match "Image.*.*\\csrss.exe" -or $_.message -match "Image.*.*\\conhost.exe" -or $_.message -match "Image.*.*\\wininit.exe" -or $_.message -match "Image.*.*\\lsm.exe" -or $_.message -match "Image.*.*\\winlogon.exe" -or $_.message -match "Image.*.*\\explorer.exe" -or $_.message -match "Image.*.*\\taskhost.exe" -or $_.message -match "Image.*.*\\Taskmgr.exe" -or $_.message -match "Image.*.*\\sihost.exe" -or $_.message -match "Image.*.*\\RuntimeBroker.exe" -or $_.message -match "Image.*.*\\smartscreen.exe" -or $_.message -match "Image.*.*\\dllhost.exe" -or $_.message -match "Image.*.*\\audiodg.exe" -or $_.message -match "Image.*.*\\wlanext.exe") -and  -not (($_.message -match "Image.*C:\\Windows\\System32\\" -or $_.message -match "Image.*C:\\Windows\\system32\\" -or $_.message -match "Image.*C:\\Windows\\SysWow64\\" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\" -or $_.message -match "Image.*C:\\Windows\\winsxs\\" -or $_.message -match "Image.*C:\\Windows\\WinSxS\\" -or $_.message -match "Image.*C:\\avast! sandbox") -or $_.message -match "Image.*.*\\SystemRoot\\System32\\" -or $_.message -match "Image.*C:\\Windows\\explorer.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_system_exe_anomaly";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_system_exe_anomaly";
            $detectedMessage = "Detects a Windows program executable started in a suspicious folder";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\svchost.exe" -or $_.message -match "Image.*.*\\rundll32.exe" -or $_.message -match "Image.*.*\\services.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\regsvr32.exe" -or $_.message -match "Image.*.*\\spoolsv.exe" -or $_.message -match "Image.*.*\\lsass.exe" -or $_.message -match "Image.*.*\\smss.exe" -or $_.message -match "Image.*.*\\csrss.exe" -or $_.message -match "Image.*.*\\conhost.exe" -or $_.message -match "Image.*.*\\wininit.exe" -or $_.message -match "Image.*.*\\lsm.exe" -or $_.message -match "Image.*.*\\winlogon.exe" -or $_.message -match "Image.*.*\\explorer.exe" -or $_.message -match "Image.*.*\\taskhost.exe" -or $_.message -match "Image.*.*\\Taskmgr.exe" -or $_.message -match "Image.*.*\\sihost.exe" -or $_.message -match "Image.*.*\\RuntimeBroker.exe" -or $_.message -match "Image.*.*\\smartscreen.exe" -or $_.message -match "Image.*.*\\dllhost.exe" -or $_.message -match "Image.*.*\\audiodg.exe" -or $_.message -match "Image.*.*\\wlanext.exe") -and -not (($_.message -match "Image.*C:\\Windows\\System32\\" -or $_.message -match "Image.*C:\\Windows\\system32\\" -or $_.message -match "Image.*C:\\Windows\\SysWow64\\" -or $_.message -match "Image.*C:\\Windows\\SysWOW64\\" -or $_.message -match "Image.*C:\\Windows\\winsxs\\" -or $_.message -match "Image.*C:\\Windows\\WinSxS\\" -or $_.message -match "Image.*C:\\avast! sandbox") -or $_.message -match "Image.*.*\\SystemRoot\\System32\\" -or $_.message -match "Image.*C:\\Windows\\explorer.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
