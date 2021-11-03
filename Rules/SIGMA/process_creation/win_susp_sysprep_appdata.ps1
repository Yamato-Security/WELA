# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\sysprep.exe") -and ($_.message -match "CommandLine.*.*\\AppData\\")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_sysprep_appdata";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_sysprep_appdata";
            $detectedMessage = "Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\sysprep.exe") -and ($_.message -match "CommandLine.*.*\\AppData\\")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
