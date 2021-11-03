# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*tracert -h 10 yahoo.com" -or $_.message -match "CommandLine.*.*.WSqmCons))|iex;" -or $_.message -match "CommandLine.*.*Fr`omBa`se6`4Str`ing") -or ($_.message -match "CommandLine.*.*net use https://docs.live.net" -and $_.message -match "CommandLine.*.*@aol.co.uk"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_turla_comrat_may20";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_turla_comrat_may20";
            $detectedMessage = "Detects commands used by Turla group as reported by ESET in May 2020";
            $result = $event | where { $_.ID -eq "1" -and (($_.message -match "CommandLine.*.*tracert -h 10 yahoo.com" -or $_.message -match "CommandLine.*.*.WSqmCons\)\)|iex;" -or $_.message -match "CommandLine.*.*Fr`omBa`se6`4Str`ing") -or ($_.message -match "CommandLine.*.*net use https://docs.live.net" -and $_.message -match "CommandLine.*.*@aol.co.uk")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMesssage;
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
