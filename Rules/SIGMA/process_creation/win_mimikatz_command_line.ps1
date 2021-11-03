# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*DumpCreds" -or $_.message -match "CommandLine.*.*invoke-mimikatz") -or (($_.message -match "CommandLine.*.*rpc" -or $_.message -match "CommandLine.*.*token" -or $_.message -match "CommandLine.*.*crypto" -or $_.message -match "CommandLine.*.*dpapi" -or $_.message -match "CommandLine.*.*sekurlsa" -or $_.message -match "CommandLine.*.*kerberos" -or $_.message -match "CommandLine.*.*lsadump" -or $_.message -match "CommandLine.*.*privilege" -or $_.message -match "CommandLine.*.*process") -and ($_.message -match "CommandLine.*.*::")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_mimikatz_command_line";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_mimikatz_command_line";
            $detectedMessage = "Detection well-known mimikatz command line arguments";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*DumpCreds" -or $_.message -match "CommandLine.*.*invoke-mimikatz") -or (($_.message -match "CommandLine.*.*rpc" -or $_.message -match "CommandLine.*.*token" -or $_.message -match "CommandLine.*.*crypto" -or $_.message -match "CommandLine.*.*dpapi" -or $_.message -match "CommandLine.*.*sekurlsa" -or $_.message -match "CommandLine.*.*kerberos" -or $_.message -match "CommandLine.*.*lsadump" -or $_.message -match "CommandLine.*.*privilege" -or $_.message -match "CommandLine.*.*process") -and ($_.message -match "CommandLine.*.*::")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
