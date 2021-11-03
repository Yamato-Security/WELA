# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "17" -or $_.ID -eq "18")) -and (($_.message -match "PipeName.*.*\MSSE-" -and $_.message -match "PipeName.*.*-server") -or $_.message -match "PipeName.*\postex_" -or $_.message -match "PipeName.*\postex_ssh_" -or $_.message -match "PipeName.*\status_" -or $_.message -match "PipeName.*\msagent_")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_mal_cobaltstrike";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_mal_cobaltstrike";
            $detectedMessage = "Detects the creation of a named pipe as used by CobaltStrike";
            $result = $event |  where { ((($_.ID -eq "17" -or $_.ID -eq "18")) -and (($_.message -match "PipeName.*.*\\MSSE-" -and $_.message -match "PipeName.*.*-server") -or $_.message -match "PipeName.*\\postex_" -or $_.message -match "PipeName.*\\postex_ssh_" -or $_.message -match "PipeName.*\\status_" -or $_.message -match "PipeName.*\\msagent_")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
