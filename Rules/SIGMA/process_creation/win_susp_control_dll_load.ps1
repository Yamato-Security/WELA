# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\System32\control.exe" -and $_.message -match "Image.*.*\rundll32.exe ") -and  -not ($_.message -match "CommandLine.*.*Shell32.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_control_dll_load";
    $detectedMessage = "Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\System32\control.exe" -and $_.message -match "Image.*.*\rundll32.exe ") -and -not ($_.message -match "CommandLine.*.*Shell32.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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