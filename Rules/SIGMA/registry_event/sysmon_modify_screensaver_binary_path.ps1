# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and $_.message -match "TargetObject.*.*\Control Panel\Desktop\SCRNSAVE.EXE" -and  -not (($_.message -match "Image.*.*\rundll32.exe" -or $_.message -match "Image.*.*\explorer.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_modify_screensaver_binary_path";
    $detectedMessage = "Detects value modification of registry key containing path to binary used as screensaver.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and $_.message -match "TargetObject.*.*\Control Panel\Desktop\SCRNSAVE.EXE" -and -not (($_.message -match "Image.*.*\rundll32.exe" -or $_.message -match "Image.*.*\explorer.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}