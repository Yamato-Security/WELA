# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\\rundll32.exe" -and  -not ($_.message -match "ParentImage.*.*\\svchost.exe")) -and  -not (($_.message -match "ParentImage.*.*\\AppData\\Local\\.*" -or $_.message -match "ParentImage.*.*\\Microsoft\\Edge\\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_rundll32_no_params";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_rundll32_no_params";
            $detectedMessage = "Detects suspicious start of rundll32.exe without any parameters as found in CobaltStrike beacon activity";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\\rundll32.exe" -and -not ($_.message -match "ParentImage.*.*\\svchost.exe")) -and -not (($_.message -match "ParentImage.*.*\\AppData\\Local\\.*" -or $_.message -match "ParentImage.*.*\\Microsoft\\Edge\\.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
