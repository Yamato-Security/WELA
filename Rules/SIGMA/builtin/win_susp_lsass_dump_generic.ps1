# Get-WinEvent -LogName Security | where {((($_.ID -eq "4656" -and $_.message -match "ObjectName.*.*\lsass.exe" -and ($_.message -match "AccessMask.*.*0x40.*" -or $_.message -match "AccessMask.*.*0x1400.*" -or $_.message -match "AccessMask.*.*0x1000.*" -or $_.message -match "AccessMask.*.*0x100000.*" -or $_.message -match "AccessMask.*.*0x1410.*" -or $_.message -match "AccessMask.*.*0x1010.*" -or $_.message -match "AccessMask.*.*0x1438.*" -or $_.message -match "AccessMask.*.*0x143a.*" -or $_.message -match "AccessMask.*.*0x1418.*" -or $_.message -match "AccessMask.*.*0x1f0fff.*" -or $_.message -match "AccessMask.*.*0x1f1fff.*" -or $_.message -match "AccessMask.*.*0x1f2fff.*" -or $_.message -match "AccessMask.*.*0x1f3fff.*")) -or ((($_.ID -eq "4663" -and $_.message -match "ObjectName.*.*\lsass.exe" -and ($_.message -match "AccessList.*.*4484.*" -or $_.message -match "AccessList.*.*4416.*")) -and  -not (($_.message -match "ProcessName.*.*\wmiprvse.exe" -or $_.message -match "ProcessName.*.*\taskmgr.exe" -or $_.message -match "ProcessName.*.*\procexp64.exe" -or $_.message -match "ProcessName.*.*\procexp.exe" -or $_.message -match "ProcessName.*.*\lsm.exe" -or $_.message -match "ProcessName.*.*\csrss.exe" -or $_.message -match "ProcessName.*.*\wininit.exe" -or $_.message -match "ProcessName.*.*\vmtoolsd.exe" -or $_.message -match "ProcessName.*.*\minionhost.exe" -or $_.message -match "ProcessName.*.*\VsTskMgr.exe" -or $_.message -match "ProcessName.*.*\thor64.exe") -and ($_.message -match "ProcessName.*C:\Windows\System32\.*" -or $_.message -match "ProcessName.*C:\Windows\SysWow64\.*" -or $_.message -match "ProcessName.*C:\Windows\SysNative\.*" -or $_.message -match "ProcessName.*C:\Program Files\.*" -or $_.message -match "ProcessName.*C:\Windows\Temp\asgard2-agent\.*"))) -and  -not (($_.message -match "ProcessName.*C:\Program Files.*"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_lsass_dump_generic";
    $detectedMessage = "Detects process handle on LSASS process with certain access mask";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {((($_.ID -eq "4656" -and $_.message -match "ObjectName.*.*\lsass.exe" -and ($_.message -match "AccessMask.*.*0x40.*" -or $_.message -match "AccessMask.*.*0x1400.*" -or $_.message -match "AccessMask.*.*0x1000.*" -or $_.message -match "AccessMask.*.*0x100000.*" -or $_.message -match "AccessMask.*.*0x1410.*" -or $_.message -match "AccessMask.*.*0x1010.*" -or $_.message -match "AccessMask.*.*0x1438.*" -or $_.message -match "AccessMask.*.*0x143a.*" -or $_.message -match "AccessMask.*.*0x1418.*" -or $_.message -match "AccessMask.*.*0x1f0fff.*" -or $_.message -match "AccessMask.*.*0x1f1fff.*" -or $_.message -match "AccessMask.*.*0x1f2fff.*" -or $_.message -match "AccessMask.*.*0x1f3fff.*")) -or ((($_.ID -eq "4663" -and $_.message -match "ObjectName.*.*\lsass.exe" -and ($_.message -match "AccessList.*.*4484.*" -or $_.message -match "AccessList.*.*4416.*")) -and -not (($_.message -match "ProcessName.*.*\wmiprvse.exe" -or $_.message -match "ProcessName.*.*\taskmgr.exe" -or $_.message -match "ProcessName.*.*\procexp64.exe" -or $_.message -match "ProcessName.*.*\procexp.exe" -or $_.message -match "ProcessName.*.*\lsm.exe" -or $_.message -match "ProcessName.*.*\csrss.exe" -or $_.message -match "ProcessName.*.*\wininit.exe" -or $_.message -match "ProcessName.*.*\vmtoolsd.exe" -or $_.message -match "ProcessName.*.*\minionhost.exe" -or $_.message -match "ProcessName.*.*\VsTskMgr.exe" -or $_.message -match "ProcessName.*.*\thor64.exe") -and ($_.message -match "ProcessName.*C:\Windows\System32\.*" -or $_.message -match "ProcessName.*C:\Windows\SysWow64\.*" -or $_.message -match "ProcessName.*C:\Windows\SysNative\.*" -or $_.message -match "ProcessName.*C:\Program Files\.*" -or $_.message -match "ProcessName.*C:\Windows\Temp\asgard2-agent\.*"))) -and -not (($_.message -match "ProcessName.*C:\Program Files.*"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
