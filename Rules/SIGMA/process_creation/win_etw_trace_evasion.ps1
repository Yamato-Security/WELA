# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*cl" -and $_.message -match "CommandLine.*.*/Trace") -or ($_.message -match "CommandLine.*.*clear-log" -and $_.message -match "CommandLine.*.*/Trace") -or ($_.message -match "CommandLine.*.*sl" -and $_.message -match "CommandLine.*.*/e:false") -or ($_.message -match "CommandLine.*.*set-log" -and $_.message -match "CommandLine.*.*/e:false") -or ($_.message -match "CommandLine.*.*Remove-EtwTraceProvider" -and $_.message -match "CommandLine.*.*EventLog-Microsoft-Windows-WMI-Activity-Trace" -and $_.message -match "CommandLine.*.*{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}") -or ($_.message -match "CommandLine.*.*Set-EtwTraceProvider" -and $_.message -match "CommandLine.*.*{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}" -and $_.message -match "CommandLine.*.*EventLog-Microsoft-Windows-WMI-Activity-Trace" -and $_.message -match "CommandLine.*.*0x11") -or ($_.message -match "CommandLine.*.*logman" -and $_.message -match "CommandLine.*.*update" -and $_.message -match "CommandLine.*.*trace" -and $_.message -match "CommandLine.*.*--p" -and $_.message -match "CommandLine.*.*-ets"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_etw_trace_evasion";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_etw_trace_evasion";
            $detectedMessage = "Detects a command that clears or disables any ETW trace log which could indicate a logging evasion.";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*cl" -and $_.message -match "CommandLine.*.*/Trace") -or ($_.message -match "CommandLine.*.*clear-log" -and $_.message -match "CommandLine.*.*/Trace") -or ($_.message -match "CommandLine.*.*sl" -and $_.message -match "CommandLine.*.*/e:false") -or ($_.message -match "CommandLine.*.*set-log" -and $_.message -match "CommandLine.*.*/e:false") -or ($_.message -match "CommandLine.*.*Remove-EtwTraceProvider" -and $_.message -match "CommandLine.*.*EventLog-Microsoft-Windows-WMI-Activity-Trace" -and $_.message -match "CommandLine.*.*{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}") -or ($_.message -match "CommandLine.*.*Set-EtwTraceProvider" -and $_.message -match "CommandLine.*.*{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}" -and $_.message -match "CommandLine.*.*EventLog-Microsoft-Windows-WMI-Activity-Trace" -and $_.message -match "CommandLine.*.*0x11") -or ($_.message -match "CommandLine.*.*logman" -and $_.message -match "CommandLine.*.*update" -and $_.message -match "CommandLine.*.*trace" -and $_.message -match "CommandLine.*.*--p" -and $_.message -match "CommandLine.*.*-ets"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
