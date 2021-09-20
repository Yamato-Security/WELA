# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\\rpcping.exe" -and ($_.message -match "CommandLine.*.*-s.*" -or $_.message -match "CommandLine.*.*/s.*")) -and (($_.message -match "CommandLine.*.*-u.*" -and $_.message -match "CommandLine.*.*NTLM.*") -or ($_.message -match "CommandLine.*.*/u.*" -and $_.message -match "CommandLine.*.*NTLM.*") -or ($_.message -match "CommandLine.*.*-t.*" -and $_.message -match "CommandLine.*.*ncacn_np.*") -or ($_.message -match "CommandLine.*.*/t.*" -and $_.message -match "CommandLine.*.*ncacn_np.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_rpcping";
    $detectedMessage = "Detects using Rpcping.exe to send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.";

    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\rpcping.exe" -and ($_.message -match "CommandLine.*.*-s.*" -or $_.message -match "CommandLine.*.*/s.*")) -and (($_.message -match "CommandLine.*.*-u.*" -and $_.message -match "CommandLine.*.*NTLM.*") -or ($_.message -match "CommandLine.*.*/u.*" -and $_.message -match "CommandLine.*.*NTLM.*") -or ($_.message -match "CommandLine.*.*-t.*" -and $_.message -match "CommandLine.*.*ncacn_np.*") -or ($_.message -match "CommandLine.*.*/t.*" -and $_.message -match "CommandLine.*.*ncacn_np.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
