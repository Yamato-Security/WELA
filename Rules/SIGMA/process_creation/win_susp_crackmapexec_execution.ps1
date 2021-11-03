# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*cmd.exe /Q /c .* 1> \\\\.*\\.*\\.* 2>&1" -or $_.message -match "CommandLine.*.*cmd.exe /C .* > \\\\.*\\.*\\.* 2>&1" -or $_.message -match "CommandLine.*.*cmd.exe /C .* > .*\\Temp\\.* 2>&1") -and ($_.message -match "CommandLine.*.*powershell.exe -exec bypass -noni -nop -w 1 -C "" -or $_.message -match "CommandLine.*.*powershell.exe -noni -nop -w 1 -enc ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_crackmapexec_execution";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_crackmapexec_execution";
            $detectedMessage = "Detect various execution methods of the CrackMapExec pentesting framework";
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*cmd.exe /Q /c .* 1> \\\\.*\\.*\\.* 2>&1" -or $_.message -match "CommandLine.*.*cmd.exe /C .* > \\\\.*\\.*\\.* 2>&1" -or $_.message -match "CommandLine.*.*cmd.exe /C .* > .*\\Temp\\.* 2>&1") -and ($_.message -match "CommandLine.*.*powershell.exe -exec bypass -noni -nop -w 1 -C """" -or $_.message -match ""CommandLine.*.*powershell.exe -noni -nop -w 1 -enc """)) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
