# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and (($_.message -match "Image.*.*\\rundll32.exe") -or ($_.message -match "Description.*.*Windows-Hostprozess (Rundll32)")) -and ($_.message -match "CommandLine.*.*Default.GetString" -or $_.message -match "CommandLine.*.*FromBase64String")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_powershell_dll_execution";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_powershell_dll_execution";
            $detectedMessage = "Detects PowerShell Strings applied to rundll as seen in PowerShdll.dll";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.ID -eq "1") -and (($_.message -match "Image.*.*\\rundll32.exe") -or ($_.message -match "Description.*.*Windows-Hostprozess (Rundll32)")) -and ($_.message -match "CommandLine.*.*Default.GetString" -or $_.message -match "CommandLine.*.*FromBase64String")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
