# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*New-MailboxExport.*" -and $_.message -match "CommandLine.*.* -Mailbox .*" -and $_.message -match "CommandLine.*.* -FilePath \127.0.0.1\C$.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_mailboxexport_share";
    $detectedMessage = "Detects a PowerShell New-MailboxExportRequest that exports a mailbox to a local share, as used in ProxyShell exploitations";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*New-MailboxExport.*" -and $_.message -match "CommandLine.*.* -Mailbox .*" -and $_.message -match "CommandLine.*.* -FilePath \\127.0.0.1\\C$.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
