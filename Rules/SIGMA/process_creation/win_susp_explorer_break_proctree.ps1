# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*explorer.exe.*" -and $_.message -match "CommandLine.*.* /root,.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_explorer_break_proctree";
    $detectedMessage = "Detects a command line process that uses explorer.exe /root, which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*explorer.exe.*" -and $_.message -match "CommandLine.*.* /root,.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
