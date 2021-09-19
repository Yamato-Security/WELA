# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*DumpCreds.*" -or $_.message -match "CommandLine.*.*invoke-mimikatz.*") -or (($_.message -match "CommandLine.*.*rpc.*" -or $_.message -match "CommandLine.*.*token.*" -or $_.message -match "CommandLine.*.*crypto.*" -or $_.message -match "CommandLine.*.*dpapi.*" -or $_.message -match "CommandLine.*.*sekurlsa.*" -or $_.message -match "CommandLine.*.*kerberos.*" -or $_.message -match "CommandLine.*.*lsadump.*" -or $_.message -match "CommandLine.*.*privilege.*" -or $_.message -match "CommandLine.*.*process.*") -and ($_.message -match "CommandLine.*.*::.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_mimikatz_command_line";
    $detectedMessage = "Detection well-known mimikatz command line arguments";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*DumpCreds.*" -or $_.message -match "CommandLine.*.*invoke-mimikatz.*") -or (($_.message -match "CommandLine.*.*rpc.*" -or $_.message -match "CommandLine.*.*token.*" -or $_.message -match "CommandLine.*.*crypto.*" -or $_.message -match "CommandLine.*.*dpapi.*" -or $_.message -match "CommandLine.*.*sekurlsa.*" -or $_.message -match "CommandLine.*.*kerberos.*" -or $_.message -match "CommandLine.*.*lsadump.*" -or $_.message -match "CommandLine.*.*privilege.*" -or $_.message -match "CommandLine.*.*process.*") -and ($_.message -match "CommandLine.*.*::.*")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
