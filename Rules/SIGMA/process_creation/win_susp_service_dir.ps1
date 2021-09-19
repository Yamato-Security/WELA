# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\Users\Public\.*" -or $_.message -match "Image.*.*\$Recycle.bin.*" -or $_.message -match "Image.*.*\Users\All Users\.*" -or $_.message -match "Image.*.*\Users\Default\.*" -or $_.message -match "Image.*.*\Users\Contacts\.*" -or $_.message -match "Image.*.*\Users\Searches\.*" -or $_.message -match "Image.*.*C:\Perflogs\.*" -or $_.message -match "Image.*.*\config\systemprofile\.*" -or $_.message -match "Image.*.*\Windows\Fonts\.*" -or $_.message -match "Image.*.*\Windows\IME\.*" -or $_.message -match "Image.*.*\Windows\addins\.*") -and ($_.message -match "ParentImage.*.*\services.exe" -or $_.message -match "ParentImage.*.*\svchost.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_service_dir";
    $detectedMessage = "Detects a service binary running in a suspicious directory";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\Users\Public\.*" -or $_.message -match "Image.*.*\$Recycle.bin.*" -or $_.message -match "Image.*.*\Users\All Users\.*" -or $_.message -match "Image.*.*\Users\Default\.*" -or $_.message -match "Image.*.*\Users\Contacts\.*" -or $_.message -match "Image.*.*\Users\Searches\.*" -or $_.message -match "Image.*.*C:\Perflogs\.*" -or $_.message -match "Image.*.*\config\systemprofile\.*" -or $_.message -match "Image.*.*\Windows\Fonts\.*" -or $_.message -match "Image.*.*\Windows\IME\.*" -or $_.message -match "Image.*.*\Windows\addins\.*") -and ($_.message -match "ParentImage.*.*\services.exe" -or $_.message -match "ParentImage.*.*\svchost.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
