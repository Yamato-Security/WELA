# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*Execute" -and $_.message -match "CommandLine.*.*CreateObject" -and $_.message -match "CommandLine.*.*RegRead" -and $_.message -match "CommandLine.*.*window.close" -and $_.message -match "CommandLine.*.*\\Microsoft\\Windows\\CurrentVersion") -and  -not (($_.message -match "CommandLine.*.*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_vbscript_unc2452";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_vbscript_unc2452";
            $detectedMessage = "Detects suspicious inline VBScript keywords as used by UNC2452";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*Execute" -and $_.message -match "CommandLine.*.*CreateObject" -and $_.message -match "CommandLine.*.*RegRead" -and $_.message -match "CommandLine.*.*window.close" -and $_.message -match "CommandLine.*.*\\Microsoft\\Windows\\CurrentVersion") -and -not (($_.message -match "CommandLine.*.*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
