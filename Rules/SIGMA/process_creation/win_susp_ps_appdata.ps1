# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*powershell.*" -and $_.message -match "CommandLine.*.*\\AppData\\.*" -and ($_.message -match "CommandLine.*.*Local\\.*" -or $_.message -match "CommandLine.*.*Roaming\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_ps_appdata";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_ps_appdata";
            $detectedMessage = "Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*/c.*" -and $_.message -match "CommandLine.*.*powershell.*" -and $_.message -match "CommandLine.*.*\\AppData\\.*" -and ($_.message -match "CommandLine.*.*Local\\.*" -or $_.message -match "CommandLine.*.*Roaming\\.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
