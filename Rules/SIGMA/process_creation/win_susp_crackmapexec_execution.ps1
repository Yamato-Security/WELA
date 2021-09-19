# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*cmd.exe /Q /c .* 1> \\.*\.*\.* 2>&1" -or $_.message -match "CommandLine.*.*cmd.exe /C .* > \\.*\.*\.* 2>&1" -or $_.message -match "CommandLine.*.*cmd.exe /C .* > .*\Temp\.* 2>&1") -and ($_.message -match "CommandLine.*.*powershell.exe -exec bypass -noni -nop -w 1 -C ".*" -or $_.message -match "CommandLine.*.*powershell.exe -noni -nop -w 1 -enc .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_crackmapexec_execution";
    $detectedMessage = "Detect various execution methods of the CrackMapExec pentesting framework";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*cmd.exe /Q /c .* 1> \\.*\.*\.* 2>&1" -or $_.message -match "CommandLine.*.*cmd.exe /C .* > \\.*\.*\.* 2>&1" -or $_.message -match "CommandLine.*.*cmd.exe /C .* > .*\Temp\.* 2>&1") -and ($_.message -match "CommandLine.*.*powershell.exe -exec bypass -noni -nop -w 1 -C "".*"" -or $_.message -match ""CommandLine.*.*powershell.exe -noni -nop -w 1 -enc .*""")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
