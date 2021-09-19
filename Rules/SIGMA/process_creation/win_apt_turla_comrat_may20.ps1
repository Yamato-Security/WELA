# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*tracert -h 10 yahoo.com.*" -or $_.message -match "CommandLine.*.*.WSqmCons))|iex;.*" -or $_.message -match "CommandLine.*.*Fr`omBa`se6`4Str`ing.*") -or ($_.message -match "CommandLine.*.*net use https://docs.live.net.*" -and $_.message -match "CommandLine.*.*@aol.co.uk.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_turla_comrat_may20";
    $detectedMessage = "Detects commands used by Turla group as reported by ESET in May 2020";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*tracert -h 10 yahoo.com.*" -or $_.message -match "CommandLine.*.*.WSqmCons))|iex;.*" -or $_.message -match "CommandLine.*.*Fr`omBa`se6`4Str`ing.*") -or ($_.message -match "CommandLine.*.*net use https://docs.live.net.*" -and $_.message -match "CommandLine.*.*@aol.co.uk.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
