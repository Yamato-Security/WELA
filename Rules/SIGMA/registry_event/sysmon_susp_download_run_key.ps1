# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "Image.*.*\Downloads\.*" -or $_.message -match "Image.*.*\Temporary Internet Files\Content.Outlook\.*" -or $_.message -match "Image.*.*\Local Settings\Temporary Internet Files\.*") -and $_.message -match "TargetObject.*.*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_susp_download_run_key";
    $detectedMessage = "!detection!"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "Image.*.*\Downloads\.*" -or $_.message -match "Image.*.*\Temporary Internet Files\Content.Outlook\.*" -or $_.message -match "Image.*.*\Local Settings\Temporary Internet Files\.*") -and $_.message -match "TargetObject.*.*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
