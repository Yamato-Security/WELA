# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "Image.*.*\GUP.exe" -and  -not (($_.message -match "Image.*.*\Users\.*\AppData\Local\Notepad++\updater\GUP.exe" -or $_.message -match "Image.*.*\Users\.*\AppData\Roaming\Notepad++\updater\GUP.exe" -or $_.message -match "Image.*.*\Program Files\Notepad++\updater\GUP.exe" -or $_.message -match "Image.*.*\Program Files (x86)\Notepad++\updater\GUP.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_gup";
    $detectedMessage = "Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and $_.message -match "Image.*.*\GUP.exe" -and -not (($_.message -match "Image.*.*\Users\.*\AppData\Local\Notepad++\updater\GUP.exe" -or $_.message -match "Image.*.*\Users\.*\AppData\Roaming\Notepad++\updater\GUP.exe" -or $_.message -match "Image.*.*\Program Files\Notepad++\updater\GUP.exe" -or $_.message -match "Image.*.*\Program Files (x86)\Notepad++\updater\GUP.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
