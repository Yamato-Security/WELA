# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Invoke-ATHRemoteFXvGPUDisablementCommand .*" -and ($_.message -match "CommandLine.*.*-ModuleName .*" -or $_.message -match "CommandLine.*.*-ModulePath .*" -or $_.message -match "CommandLine.*.*-ScriptBlock .*" -or $_.message -match "CommandLine.*.*-RemoteFXvGPUDisablementFilePath.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Windows PowerShell | where { ($_.message -match "HostApplication.*.*Invoke-ATHRemoteFXvGPUDisablementCommand .*" -and ($_.message -match "HostApplication.*.*-ModuleName .*" -or $_.message -match "HostApplication.*.*-ModulePath .*" -or $_.message -match "HostApplication.*.*-ScriptBlock .*" -or $_.message -match "HostApplication.*.*-RemoteFXvGPUDisablementFilePath.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where { ($_.message -match "ContextInfo.*.*Invoke-ATHRemoteFXvGPUDisablementCommand .*" -and ($_.message -match "ContextInfo.*.*-ModuleName .*" -or $_.message -match "ContextInfo.*.*-ModulePath .*" -or $_.message -match "ContextInfo.*.*-ScriptBlock .*" -or $_.message -match "ContextInfo.*.*-RemoteFXvGPUDisablementFilePath.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_susp_athremotefxvgpudisablementcommand";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_athremotefxvgpudisablementcommand";
            $detectedMessage = "RemoteFXvGPUDisablement.exe is an abusable, signed PowerShell host executable that was introduced in Windows 10 and Server 2019 (OS Build 17763.1339)."
            $results = @();
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Invoke-ATHRemoteFXvGPUDisablementCommand .*" -and ($_.message -match "CommandLine.*.*-ModuleName .*" -or $_.message -match "CommandLine.*.*-ModulePath .*" -or $_.message -match "CommandLine.*.*-ScriptBlock .*" -or $_.message -match "CommandLine.*.*-RemoteFXvGPUDisablementFilePath.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.message -match "HostApplication.*.*Invoke-ATHRemoteFXvGPUDisablementCommand .*" -and ($_.message -match "HostApplication.*.*-ModuleName .*" -or $_.message -match "HostApplication.*.*-ModulePath .*" -or $_.message -match "HostApplication.*.*-ScriptBlock .*" -or $_.message -match "HostApplication.*.*-RemoteFXvGPUDisablementFilePath.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.message -match "ContextInfo.*.*Invoke-ATHRemoteFXvGPUDisablementCommand .*" -and ($_.message -match "ContextInfo.*.*-ModuleName .*" -or $_.message -match "ContextInfo.*.*-ModulePath .*" -or $_.message -match "ContextInfo.*.*-ScriptBlock .*" -or $_.message -match "ContextInfo.*.*-RemoteFXvGPUDisablementFilePath.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;    
                    Write-Host $result;
                    Write-Host
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
