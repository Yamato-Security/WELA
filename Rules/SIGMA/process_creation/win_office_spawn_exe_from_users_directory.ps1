# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\WINWORD.EXE" -or $_.message -match "ParentImage.*.*\EXCEL.EXE" -or $_.message -match "ParentImage.*.*\POWERPNT.exe" -or $_.message -match "ParentImage.*.*\MSPUB.exe" -or $_.message -match "ParentImage.*.*\VISIO.exe") -and $_.message -match "Image.*C:\users\.*" -and $_.message -match "Image.*.*.exe") -and  -not ($_.message -match "Image.*.*\Teams.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_office_spawn_exe_from_users_directory";
    $detectedMessage = "Detects an executable in the users directory started from Microsoft Word, Excel, Powerpoint, Publisher or Visio";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\WINWORD.EXE" -or $_.message -match "ParentImage.*.*\EXCEL.EXE" -or $_.message -match "ParentImage.*.*\POWERPNT.exe" -or $_.message -match "ParentImage.*.*\MSPUB.exe" -or $_.message -match "ParentImage.*.*\VISIO.exe") -and $_.message -match "Image.*C:\users\.*" -and $_.message -match "Image.*.*.exe") -and -not ($_.message -match "Image.*.*\Teams.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
