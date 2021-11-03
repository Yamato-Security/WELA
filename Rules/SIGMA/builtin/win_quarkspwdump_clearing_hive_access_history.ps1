# Get-WinEvent -LogName System | where {($_.ID -eq "16" -and $_.message -match "HiveName.*.*\AppData\Local\Temp\SAM" -and $_.message -match "HiveName.*.*.dmp") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_quarkspwdump_clearing_hive_access_history";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_quarkspwdump_clearing_hive_access_history";
            $detectedMessage = "Detects QuarksPwDump clearing access history in hive";
            $result = $event |  where { ($_.ID -eq "16" -and $_.message -match "HiveName.*.*\\AppData\\Local\\Temp\\SAM" -and $_.message -match "HiveName.*.*.dmp") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
