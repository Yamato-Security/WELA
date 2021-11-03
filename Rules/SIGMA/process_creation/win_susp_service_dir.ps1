# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\Users\\Public\\" -or $_.message -match "Image.*.*\\$Recycle.bin" -or $_.message -match "Image.*.*\\Users\\All Users\\" -or $_.message -match "Image.*.*\\Users\\Default\\" -or $_.message -match "Image.*.*\\Users\\Contacts\\" -or $_.message -match "Image.*.*\\Users\\Searches\\" -or $_.message -match "Image.*.*C:\\Perflogs\\" -or $_.message -match "Image.*.*\\config\\systemprofile\\" -or $_.message -match "Image.*.*\\Windows\\Fonts\\" -or $_.message -match "Image.*.*\\Windows\\IME\\" -or $_.message -match "Image.*.*\\Windows\\addins\\") -and ($_.message -match "ParentImage.*.*\\services.exe" -or $_.message -match "ParentImage.*.*\\svchost.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_service_dir";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_service_dir";
            $detectedMessage = "Detects a service binary running in a suspicious directory";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\Users\\Public\\" -or $_.message -match "Image.*.*\\$Recycle.bin" -or $_.message -match "Image.*.*\\Users\\All Users\\" -or $_.message -match "Image.*.*\\Users\\Default\\" -or $_.message -match "Image.*.*\\Users\\Contacts\\" -or $_.message -match "Image.*.*\\Users\\Searches\\" -or $_.message -match "Image.*.*C:\\Perflogs\\" -or $_.message -match "Image.*.*\\config\\systemprofile\\" -or $_.message -match "Image.*.*\\Windows\\Fonts\\" -or $_.message -match "Image.*.*\\Windows\\IME\\" -or $_.message -match "Image.*.*\\Windows\\addins\\") -and ($_.message -match "ParentImage.*.*\\services.exe" -or $_.message -match "ParentImage.*.*\\svchost.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
