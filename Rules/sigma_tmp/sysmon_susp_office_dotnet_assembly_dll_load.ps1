# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and ($_.message -match "Image.*.*\winword.exe" -or $_.message -match "Image.*.*\powerpnt.exe" -or $_.message -match "Image.*.*\excel.exe" -or $_.message -match "Image.*.*\outlook.exe") -and ($_.message -match "ImageLoaded.*C:\Windows\assembly\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_susp_office_dotnet_assembly_dll_load";
    $detectedMessage = "Detects any assembly DLL being loaded by an Office Product"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "7" -and ($_.message -match "Image.*.*\winword.exe" -or $_.message -match "Image.*.*\powerpnt.exe" -or $_.message -match "Image.*.*\excel.exe" -or $_.message -match "Image.*.*\outlook.exe") -and ($_.message -match "ImageLoaded.*C:\Windows\assembly\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
