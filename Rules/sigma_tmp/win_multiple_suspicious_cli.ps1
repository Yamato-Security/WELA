# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*arp.exe.*" -or $_.message -match "CommandLine.*.*at.exe.*" -or $_.message -match "CommandLine.*.*attrib.exe.*" -or $_.message -match "CommandLine.*.*cscript.exe.*" -or $_.message -match "CommandLine.*.*dsquery.exe.*" -or $_.message -match "CommandLine.*.*hostname.exe.*" -or $_.message -match "CommandLine.*.*ipconfig.exe.*" -or $_.message -match "CommandLine.*.*mimikatz.exe.*" -or $_.message -match "CommandLine.*.*nbtstat.exe.*" -or $_.message -match "CommandLine.*.*net.exe.*" -or $_.message -match "CommandLine.*.*netsh.exe.*" -or $_.message -match "CommandLine.*.*nslookup.exe.*" -or $_.message -match "CommandLine.*.*ping.exe.*" -or $_.message -match "CommandLine.*.*quser.exe.*" -or $_.message -match "CommandLine.*.*qwinsta.exe.*" -or $_.message -match "CommandLine.*.*reg.exe.*" -or $_.message -match "CommandLine.*.*runas.exe.*" -or $_.message -match "CommandLine.*.*sc.exe.*" -or $_.message -match "CommandLine.*.*schtasks.exe.*" -or $_.message -match "CommandLine.*.*ssh.exe.*" -or $_.message -match "CommandLine.*.*systeminfo.exe.*" -or $_.message -match "CommandLine.*.*taskkill.exe.*" -or $_.message -match "CommandLine.*.*telnet.exe.*" -or $_.message -match "CommandLine.*.*tracert.exe.*" -or $_.message -match "CommandLine.*.*wscript.exe.*" -or $_.message -match "CommandLine.*.*xcopy.exe.*" -or $_.message -match "CommandLine.*.*pscp.exe.*" -or $_.message -match "CommandLine.*.*copy.exe.*" -or $_.message -match "CommandLine.*.*robocopy.exe.*" -or $_.message -match "CommandLine.*.*certutil.exe.*" -or $_.message -match "CommandLine.*.*vssadmin.exe.*" -or $_.message -match "CommandLine.*.*powershell.exe.*" -or $_.message -match "CommandLine.*.*wevtutil.exe.*" -or $_.message -match "CommandLine.*.*psexec.exe.*" -or $_.message -match "CommandLine.*.*bcedit.exe.*" -or $_.message -match "CommandLine.*.*wbadmin.exe.*" -or $_.message -match "CommandLine.*.*icacls.exe.*" -or $_.message -match "CommandLine.*.*diskpart.exe.*")) }  | group-object MachineName | where { $_.count -gt 5 } | select name,count | sort -desc

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_multiple_suspicious_cli";
    $detectedMessage = "Detects multiple suspicious process in a limited timeframe"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*arp.exe.*" -or $_.message -match "CommandLine.*.*at.exe.*" -or $_.message -match "CommandLine.*.*attrib.exe.*" -or $_.message -match "CommandLine.*.*cscript.exe.*" -or $_.message -match "CommandLine.*.*dsquery.exe.*" -or $_.message -match "CommandLine.*.*hostname.exe.*" -or $_.message -match "CommandLine.*.*ipconfig.exe.*" -or $_.message -match "CommandLine.*.*mimikatz.exe.*" -or $_.message -match "CommandLine.*.*nbtstat.exe.*" -or $_.message -match "CommandLine.*.*net.exe.*" -or $_.message -match "CommandLine.*.*netsh.exe.*" -or $_.message -match "CommandLine.*.*nslookup.exe.*" -or $_.message -match "CommandLine.*.*ping.exe.*" -or $_.message -match "CommandLine.*.*quser.exe.*" -or $_.message -match "CommandLine.*.*qwinsta.exe.*" -or $_.message -match "CommandLine.*.*reg.exe.*" -or $_.message -match "CommandLine.*.*runas.exe.*" -or $_.message -match "CommandLine.*.*sc.exe.*" -or $_.message -match "CommandLine.*.*schtasks.exe.*" -or $_.message -match "CommandLine.*.*ssh.exe.*" -or $_.message -match "CommandLine.*.*systeminfo.exe.*" -or $_.message -match "CommandLine.*.*taskkill.exe.*" -or $_.message -match "CommandLine.*.*telnet.exe.*" -or $_.message -match "CommandLine.*.*tracert.exe.*" -or $_.message -match "CommandLine.*.*wscript.exe.*" -or $_.message -match "CommandLine.*.*xcopy.exe.*" -or $_.message -match "CommandLine.*.*pscp.exe.*" -or $_.message -match "CommandLine.*.*copy.exe.*" -or $_.message -match "CommandLine.*.*robocopy.exe.*" -or $_.message -match "CommandLine.*.*certutil.exe.*" -or $_.message -match "CommandLine.*.*vssadmin.exe.*" -or $_.message -match "CommandLine.*.*powershell.exe.*" -or $_.message -match "CommandLine.*.*wevtutil.exe.*" -or $_.message -match "CommandLine.*.*psexec.exe.*" -or $_.message -match "CommandLine.*.*bcedit.exe.*" -or $_.message -match "CommandLine.*.*wbadmin.exe.*" -or $_.message -match "CommandLine.*.*icacls.exe.*" -or $_.message -match "CommandLine.*.*diskpart.exe.*")) } | group-object MachineName | where { $_.count -gt 5 } | select name,count | sort -desc;
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