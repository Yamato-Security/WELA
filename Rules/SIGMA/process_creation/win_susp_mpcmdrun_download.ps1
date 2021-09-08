# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*MpCmdRun.exe.*" -or $_.message -match "Description.*Microsoft Malware Protection Command Line Utility") -and ($_.message -match "CommandLine.*.*DownloadFile.*" -and $_.message -match "CommandLine.*.*url.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_mpcmdrun_download";
    $detectedMessage = "Detect the use of Windows Defender to download payloads ";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*MpCmdRun.exe.*" -or $_.message -match "Description.*Microsoft Malware Protection Command Line Utility") -and ($_.message -match "CommandLine.*.*DownloadFile.*" -and $_.message -match "CommandLine.*.*url.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
