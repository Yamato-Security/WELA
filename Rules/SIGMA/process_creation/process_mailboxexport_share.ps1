# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*New-MailboxExport" -and $_.message -match "CommandLine.*.* -Mailbox " -and $_.message -match "CommandLine.*.* -FilePath \127.0.0.1\C$") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_mailboxexport_share";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "process_mailboxexport_share";
            $detectedMessage = "Detects a PowerShell New-MailboxExportRequest that exports a mailbox to a local share, as used in ProxyShell exploitations";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*New-MailboxExport" -and $_.message -match "CommandLine.*.* -Mailbox " -and $_.message -match "CommandLine.*.* -FilePath \\127.0.0.1\\C$") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
