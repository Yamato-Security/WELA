# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "tasklist" -or $_.message -match "net time" -or $_.message -match "systeminfo" -or $_.message -match "whoami" -or $_.message -match "nbtstat" -or $_.message -match "net start" -or $_.message -match "qprocess" -or $_.message -match "nslookup" -or $_.message -match "hostname.exe" -or $_.message -match "netstat -an") -or ($_.message -match "CommandLine.*.*\\net1 start" -or $_.message -match "CommandLine.*.*\\net1 user /domain" -or $_.message -match "CommandLine.*.*\\net1 group /domain" -or $_.message -match "CommandLine.*.*\\net1 group "domain admins" /domain" -or $_.message -match "CommandLine.*.*\\net1 group "Exchange Trusted Subsystem" /domain" -or $_.message -match "CommandLine.*.*\\net1 accounts /domain" -or $_.message -match "CommandLine.*.*\\net1 user net localgroup administrators"))) }  | group-object CommandLine | where { $_.count -gt 4 } | select name,count | sort -desc

function Add-Rule {

    $ruleName = "win_susp_commands_recon_activity";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_commands_recon_activity";
            $detectedMessage = "Detects a set of commands often used in recon stages by different attack groups";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "tasklist" -or $_.message -match "net time" -or $_.message -match "systeminfo" -or $_.message -match "whoami" -or $_.message -match "nbtstat" -or $_.message -match "net start" -or $_.message -match "qprocess" -or $_.message -match "nslookup" -or $_.message -match "hostname.exe" -or $_.message -match "netstat -an") -or ($_.message -match "CommandLine.*.*\\net1 start" -or $_.message -match "CommandLine.*.*\\net1 user /domain" -or $_.message -match "CommandLine.*.*\\net1 group /domain" -or $_.message -match "CommandLine.*.*\\net1 group ""domain admins"" /domain" -or $_.message -match "CommandLine.*.*\\net1 group ""Exchange Trusted Subsystem"" /domain" -or $_.message -match "CommandLine.*.*\\net1 accounts /domain" -or $_.message -match "CommandLine.*.*\\net1 user net localgroup administrators"))) }  | group-object CommandLine | where { $_.count -gt 4 } | select name, count | sort -desc;

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
