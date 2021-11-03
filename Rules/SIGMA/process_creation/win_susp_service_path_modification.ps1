# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\sc.exe" -and $_.message -match "CommandLine.*.*config" -and $_.message -match "CommandLine.*.*binpath" -and ($_.message -match "CommandLine.*.*powershell" -or $_.message -match "CommandLine.*.*cmd")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_service_path_modification";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_service_path_modification";
            $detectedMessage = "Detects service path modification to PowerShell or cmd.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\sc.exe" -and $_.message -match "CommandLine.*.*config" -and $_.message -match "CommandLine.*.*binpath" -and ($_.message -match "CommandLine.*.*powershell" -or $_.message -match "CommandLine.*.*cmd")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
