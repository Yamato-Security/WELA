# Get-WinEvent -LogName Security | where {($_.ID -eq "4799" -and $_.message -match "TargetUserName.*Administr" -and $_.message -match "CallerProcessName.*.*\\checkadmin.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*checkadmin.exe 127.0.0.1 -all" -or $_.message -match "CommandLine.*.*netsh advfirewall firewall add rule name=powershell dir=in" -or $_.message -match "CommandLine.*.*cmd /c powershell.exe -ep bypass -file c:\\s.ps1" -or $_.message -match "CommandLine.*.*/tn win32times /f" -or $_.message -match "CommandLine.*.*create win32times binPath=" -or $_.message -match "CommandLine.*.*\\c$\\windows\\system32\\devmgr.dll" -or $_.message -match "CommandLine.*.* -exec bypass -enc JgAg" -or $_.message -match "CommandLine.*.*type .*keepass\\KeePass.config.xml" -or $_.message -match "CommandLine.*.*iie.exe iie.txt" -or $_.message -match "CommandLine.*.*reg query HKEY_CURRENT_USER\\Software\\.*\\PuTTY\\Sessions\\")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_wocao";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "win_apt_wocao";
            $detectedMessage = "Detects activity mentioned in Operation Wocao report";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.ID -eq "4799" -and $_.message -match "TargetUserName.*Administr" -and $_.message -match "CallerProcessName.*.*\\checkadmin.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*checkadmin.exe 127.0.0.1 -all" -or $_.message -match "CommandLine.*.*netsh advfirewall firewall add rule name=powershell dir=in" -or $_.message -match "CommandLine.*.*cmd /c powershell.exe -ep bypass -file c:\\s.ps1" -or $_.message -match "CommandLine.*.*/tn win32times /f" -or $_.message -match "CommandLine.*.*create win32times binPath=" -or $_.message -match "CommandLine.*.*\\c$\\windows\\system32\\devmgr.dll" -or $_.message -match "CommandLine.*.* -exec bypass -enc JgAg" -or $_.message -match "CommandLine.*.*type .*keepass\\KeePass.config.xml" -or $_.message -match "CommandLine.*.*iie.exe iie.txt" -or $_.message -match "CommandLine.*.*reg query HKEY_CURRENT_USER\\Software\\.*\\PuTTY\\Sessions\\")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.count() -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;    
                    Write-Output $result;
                    Write-Output ""; 
                }
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
