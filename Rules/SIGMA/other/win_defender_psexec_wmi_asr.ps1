# Get-WinEvent | where {($_.ID -eq "1121" -and ($_.message -match "ProcessName.*.*\wmiprvse.exe" -or $_.message -match "ProcessName.*.*\psexesvc.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_defender_psexec_wmi_asr";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_defender_psexec_wmi_asr";
            $detectedMessage = "Detects blocking of process creations originating from PSExec and WMI commands";
            $result = $event |  where { ($_.ID -eq "1121" -and ($_.message -match "ProcessName.*.*\\wmiprvse.exe" -or $_.message -match "ProcessName.*.*\\psexesvc.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
