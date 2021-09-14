# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*Invoke-WMIMethod win32_process -name create -argumentlist.*" -and $_.message -match "CommandLine.*.*rundll32 c:\windows.*") -or ($_.message -match "CommandLine.*.*wmic /node:.*" -and $_.message -match "CommandLine.*.*process call create "rundll32 c:\windows.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_unc2452_ps";
    $detectedMessage = "Detects a specific PowerShell command line pattern used by the UNC2452 actors as mentioned in Microsoft and Symantec reports";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*Invoke-WMIMethod win32_process -name create -argumentlist.*" -and $_.message -match "CommandLine.*.*rundll32 c:\windows.*") -or ($_.message -match "CommandLine.*.*wmic /node:.*" -and $_.message -match "CommandLine.*.*process call create ""rundll32 c:\windows.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
