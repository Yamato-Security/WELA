# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\register-cimprovider.exe" -and $_.message -match "CommandLine.*.*-path" -and $_.message -match "CommandLine.*.*dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_register_cimprovider";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_register_cimprovider";
            $detectedMessage = "Detects using register-cimprovider.exe to execute arbitrary dll file.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\register-cimprovider.exe" -and $_.message -match "CommandLine.*.*-path" -and $_.message -match "CommandLine.*.*dll") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
