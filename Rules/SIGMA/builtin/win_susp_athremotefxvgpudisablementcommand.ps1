# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Invoke-ATHRemoteFXvGPUDisablementCommand " -and ($_.message -match "CommandLine.*.*-ModuleName " -or $_.message -match "CommandLine.*.*-ModulePath " -or $_.message -match "CommandLine.*.*-ScriptBlock " -or $_.message -match "CommandLine.*.*-RemoteFXvGPUDisablementFilePath")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Windows PowerShell | where { ($_.message -match "HostApplication.*.*Invoke-ATHRemoteFXvGPUDisablementCommand " -and ($_.message -match "HostApplication.*.*-ModuleName " -or $_.message -match "HostApplication.*.*-ModulePath " -or $_.message -match "HostApplication.*.*-ScriptBlock " -or $_.message -match "HostApplication.*.*-RemoteFXvGPUDisablementFilePath")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.message -match "ContextInfo.*.*Invoke-ATHRemoteFXvGPUDisablementCommand " -and ($_.message -match "ContextInfo.*.*-ModuleName " -or $_.message -match "ContextInfo.*.*-ModulePath " -or $_.message -match "ContextInfo.*.*-ScriptBlock " -or $_.message -match "ContextInfo.*.*-RemoteFXvGPUDisablementFilePath")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_susp_athremotefxvgpudisablementcommand";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_athremotefxvgpudisablementcommand";
            $detectedMessage = "RemoteFXvGPUDisablement.exe is an abusable, signed PowerShell host executable that was introduced in Windows 10 and Server 2019 (OS Build 17763.1339)."
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Invoke-ATHRemoteFXvGPUDisablementCommand " -and ($_.message -match "CommandLine.*.*-ModuleName " -or $_.message -match "CommandLine.*.*-ModulePath " -or $_.message -match "CommandLine.*.*-ScriptBlock " -or $_.message -match "CommandLine.*.*-RemoteFXvGPUDisablementFilePath")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);

            $tmp = $event | where { ($_.message -match "HostApplication.*.*Invoke-ATHRemoteFXvGPUDisablementCommand " -and ($_.message -match "HostApplication.*.*-ModuleName " -or $_.message -match "HostApplication.*.*-ModulePath " -or $_.message -match "HostApplication.*.*-ScriptBlock " -or $_.message -match "HostApplication.*.*-RemoteFXvGPUDisablementFilePath")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);

            $tmp = $event | where { ($_.message -match "ContextInfo.*.*Invoke-ATHRemoteFXvGPUDisablementCommand " -and ($_.message -match "ContextInfo.*.*-ModuleName " -or $_.message -match "ContextInfo.*.*-ModulePath " -or $_.message -match "ContextInfo.*.*-ScriptBlock " -or $_.message -match "ContextInfo.*.*-RemoteFXvGPUDisablementFilePath")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
