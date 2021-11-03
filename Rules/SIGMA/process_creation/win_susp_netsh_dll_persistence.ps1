# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\netsh.exe" -and $_.message -match "CommandLine.*.*add" -and $_.message -match "CommandLine.*.*helper") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_netsh_dll_persistence";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_netsh_dll_persistence";
            $detectedMessage = "Detects persitence via netsh helper";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\netsh.exe" -and $_.message -match "CommandLine.*.*add" -and $_.message -match "CommandLine.*.*helper") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
