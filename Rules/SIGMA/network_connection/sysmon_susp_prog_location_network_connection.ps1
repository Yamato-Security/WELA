# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "3") -and (($_.message -match "Image.*.*\Users\All Users\.*" -or $_.message -match "Image.*.*\Users\Default\.*" -or $_.message -match "Image.*.*\Users\Public\.*" -or $_.message -match "Image.*.*\Users\Contacts\.*" -or $_.message -match "Image.*.*\Users\Searches\.*" -or $_.message -match "Image.*.*\config\systemprofile\.*" -or $_.message -match "Image.*.*\Windows\Fonts\.*" -or $_.message -match "Image.*.*\Windows\IME\.*" -or $_.message -match "Image.*.*\Windows\addins\.*") -or ($_.message -match "Image.*.*\$Recycle.bin") -or ($_.message -match "Image.*C:\Perflogs\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_prog_location_network_connection";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_prog_location_network_connection";
            $detectedMessage = "Detects programs with network connections running in suspicious files system locations";
            $result = $event |  where { (($_.ID -eq "3") -and (($_.message -match "Image.*.*\\Users\\All Users\\.*" -or $_.message -match "Image.*.*\\Users\\Default\\.*" -or $_.message -match "Image.*.*\\Users\\Public\\.*" -or $_.message -match "Image.*.*\\Users\\Contacts\\.*" -or $_.message -match "Image.*.*\\Users\\Searches\\.*" -or $_.message -match "Image.*.*\\config\\systemprofile\\.*" -or $_.message -match "Image.*.*\\Windows\\Fonts\\.*" -or $_.message -match "Image.*.*\\Windows\\IME\\.*" -or $_.message -match "Image.*.*\\Windows\\addins\\.*") -or ($_.message -match "Image.*.*\\$Recycle.bin") -or ($_.message -match "Image.*C:\\Perflogs\\.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
