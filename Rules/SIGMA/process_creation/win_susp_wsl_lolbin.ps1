# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\wsl.exe") -and ($_.message -match "CommandLine.*.* -e " -or $_.message -match "CommandLine.*.* --exec ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_wsl_lolbin";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_wsl_lolbin";
            $detectedMessage = "Detects Possible usage of Windows Subsystem for Linux (WSL) binary as a LOLBIN";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\wsl.exe") -and ($_.message -match "CommandLine.*.* -e " -or $_.message -match "CommandLine.*.* --exec ")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
