# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "10") -and ($_.message -match "TargetImage.*.*\lsass.exe" -and ($_.message -match "GrantedAccess.*.*0x40" -or $_.message -match "GrantedAccess.*.*0x1000" -or $_.message -match "GrantedAccess.*.*0x1400" -or $_.message -match "GrantedAccess.*.*0x100000" -or $_.message -match "GrantedAccess.*.*0x1410" -or $_.message -match "GrantedAccess.*.*0x1010" -or $_.message -match "GrantedAccess.*.*0x1438" -or $_.message -match "GrantedAccess.*.*0x143a" -or $_.message -match "GrantedAccess.*.*0x1418" -or $_.message -match "GrantedAccess.*.*0x1f0fff" -or $_.message -match "GrantedAccess.*.*0x1f1fff" -or $_.message -match "GrantedAccess.*.*0x1f2fff" -or $_.message -match "GrantedAccess.*.*0x1f3fff")) -and  -not (($_.message -match "ProcessName.*.*\wmiprvse.exe" -or $_.message -match "ProcessName.*.*\taskmgr.exe" -or $_.message -match "ProcessName.*.*\procexp64.exe" -or $_.message -match "ProcessName.*.*\procexp.exe" -or $_.message -match "ProcessName.*.*\lsm.exe" -or $_.message -match "ProcessName.*.*\MsMpEng.exe" -or $_.message -match "ProcessName.*.*\csrss.exe" -or $_.message -match "ProcessName.*.*\wininit.exe" -or $_.message -match "ProcessName.*.*\vmtoolsd.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_cred_dump_lsass_access";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_cred_dump_lsass_access";
            $detectedMessage = "Detects process access LSASS memory which is typical for credentials dumping tools";
            $result = $event |  where { (($_.ID -eq "10") -and ($_.message -match "TargetImage.*.*\\lsass.exe" -and ($_.message -match "GrantedAccess.*.*0x40" -or $_.message -match "GrantedAccess.*.*0x1000" -or $_.message -match "GrantedAccess.*.*0x1400" -or $_.message -match "GrantedAccess.*.*0x100000" -or $_.message -match "GrantedAccess.*.*0x1410" -or $_.message -match "GrantedAccess.*.*0x1010" -or $_.message -match "GrantedAccess.*.*0x1438" -or $_.message -match "GrantedAccess.*.*0x143a" -or $_.message -match "GrantedAccess.*.*0x1418" -or $_.message -match "GrantedAccess.*.*0x1f0fff" -or $_.message -match "GrantedAccess.*.*0x1f1fff" -or $_.message -match "GrantedAccess.*.*0x1f2fff" -or $_.message -match "GrantedAccess.*.*0x1f3fff")) -and -not (($_.message -match "ProcessName.*.*\\wmiprvse.exe" -or $_.message -match "ProcessName.*.*\\taskmgr.exe" -or $_.message -match "ProcessName.*.*\\procexp64.exe" -or $_.message -match "ProcessName.*.*\\procexp.exe" -or $_.message -match "ProcessName.*.*\\lsm.exe" -or $_.message -match "ProcessName.*.*\\MsMpEng.exe" -or $_.message -match "ProcessName.*.*\\csrss.exe" -or $_.message -match "ProcessName.*.*\\wininit.exe" -or $_.message -match "ProcessName.*.*\\vmtoolsd.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
