# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\WINWORD.EXE" -or $_.message -match "ParentImage.*.*\\EXCEL.EXE" -or $_.message -match "ParentImage.*.*\\POWERPNT.exe" -or $_.message -match "ParentImage.*.*\\MSPUB.exe" -or $_.message -match "ParentImage.*.*\\VISIO.exe") -and $_.message -match "Image.*C:\\users\\" -and $_.message -match "Image.*.*.exe") -and  -not ($_.message -match "Image.*.*\\Teams.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_office_spawn_exe_from_users_directory";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_office_spawn_exe_from_users_directory";
            $detectedMessage = "Detects an executable in the users directory started from Microsoft Word, Excel, Powerpoint, Publisher or Visio";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\WINWORD.EXE" -or $_.message -match "ParentImage.*.*\\EXCEL.EXE" -or $_.message -match "ParentImage.*.*\\POWERPNT.exe" -or $_.message -match "ParentImage.*.*\\MSPUB.exe" -or $_.message -match "ParentImage.*.*\\VISIO.exe") -and $_.message -match "Image.*C:\\users\\" -and $_.message -match "Image.*.*.exe") -and -not ($_.message -match "Image.*.*\\Teams.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
