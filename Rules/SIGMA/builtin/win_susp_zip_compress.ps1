# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Compress-Archive " -and $_.message -match "CommandLine.*.* -Path " -and $_.message -match "CommandLine.*.* -DestinationPath " -and $_.message -match "CommandLine.*.*$env:TEMP\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Windows PowerShell | where { ($_.message -match "HostApplication.*.*Compress-Archive " -and $_.message -match "HostApplication.*.* -Path " -and $_.message -match "HostApplication.*.* -DestinationPath " -and $_.message -match "HostApplication.*.*$env:TEMP\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.message -match "ContextInfo.*.*Compress-Archive " -and $_.message -match "ContextInfo.*.* -Path " -and $_.message -match "ContextInfo.*.* -DestinationPath " -and $_.message -match "ContextInfo.*.*$env:TEMP\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_susp_zip_compress";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_zip_compress";
            $detectedMessage = "Use living off the land tools to zip a file and stage it in the Windows temporary folder for later exfiltration";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Compress-Archive " -and $_.message -match "CommandLine.*.* -Path " -and $_.message -match "CommandLine.*.* -DestinationPath " -and $_.message -match "CommandLine.*.*$env:TEMP\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.message -match "HostApplication.*.*Compress-Archive " -and $_.message -match "HostApplication.*.* -Path " -and $_.message -match "HostApplication.*.* -DestinationPath " -and $_.message -match "HostApplication.*.*$env:TEMP\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.message -match "ContextInfo.*.*Compress-Archive " -and $_.message -match "ContextInfo.*.* -Path " -and $_.message -match "ContextInfo.*.* -DestinationPath " -and $_.message -match "ContextInfo.*.*$env:TEMP\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
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
