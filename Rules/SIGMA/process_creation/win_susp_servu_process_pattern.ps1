# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\Serv-U.exe" -and ($_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\wscript.exe" -or $_.message -match "Image.*.*\cscript.exe" -or $_.message -match "Image.*.*\sh.exe" -or $_.message -match "Image.*.*\bash.exe" -or $_.message -match "Image.*.*\schtasks.exe" -or $_.message -match "Image.*.*\regsvr32.exe" -or $_.message -match "Image.*.*\wmic.exe" -or $_.message -match "Image.*.*\mshta.exe" -or $_.message -match "Image.*.*\rundll32.exe" -or $_.message -match "Image.*.*\msiexec.exe" -or $_.message -match "Image.*.*\forfiles.exe" -or $_.message -match "Image.*.*\scriptrunner.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_servu_process_pattern";
    $detectedMessage = "Detects a suspicious process pattern which could be a sign of an exploited Serv-U service";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\Serv-U.exe" -and ($_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\wscript.exe" -or $_.message -match "Image.*.*\cscript.exe" -or $_.message -match "Image.*.*\sh.exe" -or $_.message -match "Image.*.*\bash.exe" -or $_.message -match "Image.*.*\schtasks.exe" -or $_.message -match "Image.*.*\regsvr32.exe" -or $_.message -match "Image.*.*\wmic.exe" -or $_.message -match "Image.*.*\mshta.exe" -or $_.message -match "Image.*.*\rundll32.exe" -or $_.message -match "Image.*.*\msiexec.exe" -or $_.message -match "Image.*.*\forfiles.exe" -or $_.message -match "Image.*.*\scriptrunner.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
