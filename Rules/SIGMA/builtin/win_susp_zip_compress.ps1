# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Compress-Archive .*" -and $_.message -match "CommandLine.*.* -Path .*" -and $_.message -match "CommandLine.*.* -DestinationPath .*" -and $_.message -match "CommandLine.*.*$env:TEMP\\.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Windows PowerShell | where { ($_.message -match "HostApplication.*.*Compress-Archive .*" -and $_.message -match "HostApplication.*.* -Path .*" -and $_.message -match "HostApplication.*.* -DestinationPath .*" -and $_.message -match "HostApplication.*.*$env:TEMP\\.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.message -match "ContextInfo.*.*Compress-Archive .*" -and $_.message -match "ContextInfo.*.* -Path .*" -and $_.message -match "ContextInfo.*.* -DestinationPath .*" -and $_.message -match "ContextInfo.*.*$env:TEMP\\.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_susp_zip_compress";
    $detectedMessage = "Use living off the land tools to zip a file and stage it in the Windows temporary folder for later exfiltration";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $results = @();
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Compress-Archive .*" -and $_.message -match "CommandLine.*.* -Path .*" -and $_.message -match "CommandLine.*.* -DestinationPath .*" -and $_.message -match "CommandLine.*.*$env:TEMP\\.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.message -match "HostApplication.*.*Compress-Archive .*" -and $_.message -match "HostApplication.*.* -Path .*" -and $_.message -match "HostApplication.*.* -DestinationPath .*" -and $_.message -match "HostApplication.*.*$env:TEMP\\.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.message -match "ContextInfo.*.*Compress-Archive .*" -and $_.message -match "ContextInfo.*.* -Path .*" -and $_.message -match "ContextInfo.*.* -DestinationPath .*" -and $_.message -match "ContextInfo.*.*$env:TEMP\\.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}