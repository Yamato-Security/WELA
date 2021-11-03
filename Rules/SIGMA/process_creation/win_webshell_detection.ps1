# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\w3wp.exe" -or $_.message -match "ParentImage.*.*\\php-cgi.exe" -or $_.message -match "ParentImage.*.*\\nginx.exe" -or $_.message -match "ParentImage.*.*\\httpd.exe") -or ($_.message -match "ParentImage.*.*\\apache" -or $_.message -match "ParentImage.*.*\\tomcat")) -and (($_.ID -eq "1") -and (((($_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe") -and ($_.message -match "CommandLine.*.* user " -or $_.message -match "CommandLine.*.* use " -or $_.message -match "CommandLine.*.* group ")) -or ($_.message -match "Image.*.*\\ping.exe" -and $_.message -match "CommandLine.*.* -n ") -or ($_.message -match "CommandLine.*.*&cd&echo" -or $_.message -match "CommandLine.*.*cd /d ")) -or ($_.message -match "Image.*.*\\wmic.exe" -and $_.message -match "CommandLine.*.* /node:") -or ($_.message -match "Image.*.*\\whoami.exe" -or $_.message -match "Image.*.*\\systeminfo.exe" -or $_.message -match "Image.*.*\\quser.exe" -or $_.message -match "Image.*.*\\ipconfig.exe" -or $_.message -match "Image.*.*\\pathping.exe" -or $_.message -match "Image.*.*\\tracert.exe" -or $_.message -match "Image.*.*\\netstat.exe" -or $_.message -match "Image.*.*\\schtasks.exe" -or $_.message -match "Image.*.*\\vssadmin.exe" -or $_.message -match "Image.*.*\\wevtutil.exe" -or $_.message -match "Image.*.*\\tasklist.exe") -or ($_.message -match "CommandLine.*.* Test-NetConnection " -or $_.message -match "CommandLine.*.*dir \\")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_webshell_detection";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_webshell_detection";
            $detectedMessage = "Detects certain command line parameters often used during reconnaissance activity via web shells";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\w3wp.exe" -or $_.message -match "ParentImage.*.*\\php-cgi.exe" -or $_.message -match "ParentImage.*.*\\nginx.exe" -or $_.message -match "ParentImage.*.*\\httpd.exe") -or ($_.message -match "ParentImage.*.*\\apache" -or $_.message -match "ParentImage.*.*\\tomcat")) -and (($_.ID -eq "1") -and (((($_.message -match "Image.*.*\\net.exe" -or $_.message -match "Image.*.*\\net1.exe") -and ($_.message -match "CommandLine.*.* user " -or $_.message -match "CommandLine.*.* use " -or $_.message -match "CommandLine.*.* group ")) -or ($_.message -match "Image.*.*\\ping.exe" -and $_.message -match "CommandLine.*.* -n ") -or ($_.message -match "CommandLine.*.*&cd&echo" -or $_.message -match "CommandLine.*.*cd /d ")) -or ($_.message -match "Image.*.*\\wmic.exe" -and $_.message -match "CommandLine.*.* /node:") -or ($_.message -match "Image.*.*\\whoami.exe" -or $_.message -match "Image.*.*\\systeminfo.exe" -or $_.message -match "Image.*.*\\quser.exe" -or $_.message -match "Image.*.*\\ipconfig.exe" -or $_.message -match "Image.*.*\\pathping.exe" -or $_.message -match "Image.*.*\\tracert.exe" -or $_.message -match "Image.*.*\\netstat.exe" -or $_.message -match "Image.*.*\\schtasks.exe" -or $_.message -match "Image.*.*\\vssadmin.exe" -or $_.message -match "Image.*.*\\wevtutil.exe" -or $_.message -match "Image.*.*\\tasklist.exe") -or ($_.message -match "CommandLine.*.* Test-NetConnection " -or $_.message -match "CommandLine.*.*dir \\")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
