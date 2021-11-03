# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*bitsadmin" -and $_.message -match "CommandLine.*.*/transfer" -and $_.message -match "CommandLine.*.*CSIDL_APPDATA") -or ($_.message -match "CommandLine.*.*CSIDL_SYSTEM_DRIVE") -or ($_.message -match "CommandLine.*.*\msf.ps1" -or $_.message -match "CommandLine.*.*8989 -e cmd.exe" -or $_.message -match "CommandLine.*.*system.Data.SqlClient.SqlDataAdapter($cmd); [void]$da.fill" -or $_.message -match "CommandLine.*.*-nop -w hidden -c $k=new-object" -or $_.message -match "CommandLine.*.*[Net.CredentialCache]::DefaultCredentials;IEX " -or $_.message -match "CommandLine.*.* -nop -w hidden -c $m=new-object net.webclient;$m" -or $_.message -match "CommandLine.*.*-noninteractive -executionpolicy bypass whoami" -or $_.message -match "CommandLine.*.*-noninteractive -executionpolicy bypass netstat -a" -or $_.message -match "CommandLine.*.*L3NlcnZlc") -or ($_.message -match "Image.*.*\adobe\Adobe.exe" -or $_.message -match "Image.*.*\oracle\local.exe" -or $_.message -match "Image.*.*\revshell.exe" -or $_.message -match "Image.*.*infopagesbackup\ncat.exe" -or $_.message -match "Image.*.*CSIDL_SYSTEM\cmd.exe" -or $_.message -match "Image.*.*\programdata\oracle\java.exe" -or $_.message -match "Image.*.*CSIDL_COMMON_APPDATA\comms\comms.exe" -or $_.message -match "Image.*.*\Programdata\VMware\Vmware.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_greenbug_may20";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_greenbug_may20";
            $detectedMessage = "Detects tools and process executions as observed in a Greenbug campaign in May 2020";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*bitsadmin" -and $_.message -match "CommandLine.*.*/transfer" -and $_.message -match "CommandLine.*.*CSIDL_APPDATA") -or ($_.message -match "CommandLine.*.*CSIDL_SYSTEM_DRIVE") -or ($_.message -match "CommandLine.*.*\\msf.ps1" -or $_.message -match "CommandLine.*.*8989 -e cmd.exe" -or $_.message -match "CommandLine.*.*system.Data.SqlClient.SqlDataAdapter($cmd); [void]$da.fill" -or $_.message -match "CommandLine.*.*-nop -w hidden -c $k=new-object" -or $_.message -match "CommandLine.*.*[Net.CredentialCache]::DefaultCredentials;IEX " -or $_.message -match "CommandLine.*.* -nop -w hidden -c $m=new-object net.webclient;$m" -or $_.message -match "CommandLine.*.*-noninteractive -executionpolicy bypass whoami" -or $_.message -match "CommandLine.*.*-noninteractive -executionpolicy bypass netstat -a" -or $_.message -match "CommandLine.*.*L3NlcnZlc") -or ($_.message -match "Image.*.*\\adobe\\Adobe.exe" -or $_.message -match "Image.*.*\\oracle\\local.exe" -or $_.message -match "Image.*.*\\revshell.exe" -or $_.message -match "Image.*.*infopagesbackup\\ncat.exe" -or $_.message -match "Image.*.*CSIDL_SYSTEM\\cmd.exe" -or $_.message -match "Image.*.*\\programdata\\oracle\\java.exe" -or $_.message -match "Image.*.*CSIDL_COMMON_APPDATA\\comms\\comms.exe" -or $_.message -match "Image.*.*\\Programdata\\VMware\\Vmware.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
