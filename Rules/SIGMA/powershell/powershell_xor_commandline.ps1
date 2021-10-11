# Get-WinEvent -LogName Windows PowerShell | where {($_.ID -eq "400" -and $_.message -match "HostName.*ConsoleHost" -and ($_.message -match "CommandLine.*.*bxor.*" -or $_.message -match "CommandLine.*.*join.*" -or $_.message -match "CommandLine.*.*char.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_xor_commandline";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_xor_commandline";
            $detectedMessage = "Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands.";
            $result = $event |  where { ($_.ID -eq "400" -and $_.message -match "HostName.*ConsoleHost" -and ($_.message -match "CommandLine.*.*bxor.*" -or $_.message -match "CommandLine.*.*join.*" -or $_.message -match "CommandLine.*.*char.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
