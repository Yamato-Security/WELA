# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and (($_.message -match "Image.*.*\rundll32.exe") -or ($_.message -match "Description.*.*Windows-Hostprozess (Rundll32).*")) -and ($_.message -match "CommandLine.*.*Default.GetString.*" -or $_.message -match "CommandLine.*.*FromBase64String.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_powershell_dll_execution";
    $detectedMessage = "Detects PowerShell Strings applied to rundll as seen in PowerShdll.dll";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.ID -eq "1") -and (($_.message -match "Image.*.*\rundll32.exe") -or ($_.message -match "Description.*.*Windows-Hostprozess (Rundll32).*")) -and ($_.message -match "CommandLine.*.*Default.GetString.*" -or $_.message -match "CommandLine.*.*FromBase64String.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
