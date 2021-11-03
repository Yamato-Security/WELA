# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*e=Access&" -and $_.message -match "CommandLine.*.*y=Guest&" -and $_.message -match "CommandLine.*.*&p=" -and $_.message -match "CommandLine.*.*&c=" -and $_.message -match "CommandLine.*.*&k=") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_screenconnect_access";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_screenconnect_access";
            $detectedMessage = "Detects ScreenConnect program starts that establish a remote access to that system (not meeting, not remote support)";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*e=Access&" -and $_.message -match "CommandLine.*.*y=Guest&" -and $_.message -match "CommandLine.*.*&p=" -and $_.message -match "CommandLine.*.*&c=" -and $_.message -match "CommandLine.*.*&k=") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
