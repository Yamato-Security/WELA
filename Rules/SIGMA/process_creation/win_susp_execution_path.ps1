# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\$Recycle.bin\.*" -or $_.message -match "Image.*.*\config\systemprofile\.*" -or $_.message -match "Image.*.*\Intel\Logs\.*" -or $_.message -match "Image.*.*\RSA\MachineKeys\.*" -or $_.message -match "Image.*.*\Users\All Users\.*" -or $_.message -match "Image.*.*\Users\Default\.*" -or $_.message -match "Image.*.*\Users\NetworkService\.*" -or $_.message -match "Image.*.*\Users\Public\.*" -or $_.message -match "Image.*.*\Windows\addins\.*" -or $_.message -match "Image.*.*\Windows\debug\.*" -or $_.message -match "Image.*.*\Windows\Fonts\.*" -or $_.message -match "Image.*.*\Windows\Help\.*" -or $_.message -match "Image.*.*\Windows\IME\.*" -or $_.message -match "Image.*.*\Windows\Media\.*" -or $_.message -match "Image.*.*\Windows\repair\.*" -or $_.message -match "Image.*.*\Windows\security\.*" -or $_.message -match "Image.*.*\Windows\system32\config\systemprofile\.*" -or $_.message -match "Image.*.*\Windows\System32\Tasks\.*" -or $_.message -match "Image.*.*\Windows\Tasks\.*") -or $_.message -match "Image.*C:\Perflogs\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_execution_path";
    $detectedMessage = "Detects a suspicious execution from an uncommon folder";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\$Recycle.bin\.*" -or $_.message -match "Image.*.*\config\systemprofile\.*" -or $_.message -match "Image.*.*\Intel\Logs\.*" -or $_.message -match "Image.*.*\RSA\MachineKeys\.*" -or $_.message -match "Image.*.*\Users\All Users\.*" -or $_.message -match "Image.*.*\Users\Default\.*" -or $_.message -match "Image.*.*\Users\NetworkService\.*" -or $_.message -match "Image.*.*\Users\Public\.*" -or $_.message -match "Image.*.*\Windows\addins\.*" -or $_.message -match "Image.*.*\Windows\debug\.*" -or $_.message -match "Image.*.*\Windows\Fonts\.*" -or $_.message -match "Image.*.*\Windows\Help\.*" -or $_.message -match "Image.*.*\Windows\IME\.*" -or $_.message -match "Image.*.*\Windows\Media\.*" -or $_.message -match "Image.*.*\Windows\repair\.*" -or $_.message -match "Image.*.*\Windows\security\.*" -or $_.message -match "Image.*.*\Windows\system32\config\systemprofile\.*" -or $_.message -match "Image.*.*\Windows\System32\Tasks\.*" -or $_.message -match "Image.*.*\Windows\Tasks\.*") -or $_.message -match "Image.*C:\Perflogs\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
