# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*C:\Windows\hh.exe" -and ($_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\wscript.exe" -or $_.message -match "Image.*.*\cscript.exe" -or $_.message -match "Image.*.*\regsvr32.exe" -or $_.message -match "Image.*.*\wmic.exe" -or $_.message -match "Image.*.*\rundll32.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_html_help_spawn";
    $detectedMessage = "Detects a suspicious child process of a Microsoft HTML Help system when executing compiled HTML files (.chm)"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "ParentImage.*C:\Windows\hh.exe" -and ($_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\wscript.exe" -or $_.message -match "Image.*.*\cscript.exe" -or $_.message -match "Image.*.*\regsvr32.exe" -or $_.message -match "Image.*.*\wmic.exe" -or $_.message -match "Image.*.*\rundll32.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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