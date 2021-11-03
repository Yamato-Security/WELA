# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "3") -and (($_.message -match "Image.*.*\Users\All Users\" -or $_.message -match "Image.*.*\Users\Default\" -or $_.message -match "Image.*.*\Users\Public\" -or $_.message -match "Image.*.*\Users\Contacts\" -or $_.message -match "Image.*.*\Users\Searches\" -or $_.message -match "Image.*.*\config\systemprofile\" -or $_.message -match "Image.*.*\Windows\Fonts\" -or $_.message -match "Image.*.*\Windows\IME\" -or $_.message -match "Image.*.*\Windows\addins\") -or ($_.message -match "Image.*.*\$Recycle.bin") -or ($_.message -match "Image.*C:\Perflogs\"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_prog_location_network_connection";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_prog_location_network_connection";
            $detectedMessage = "Detects programs with network connections running in suspicious files system locations";
            $result = $event |  where { (($_.ID -eq "3") -and (($_.message -match "Image.*.*\\Users\\All Users\\" -or $_.message -match "Image.*.*\\Users\\Default\\" -or $_.message -match "Image.*.*\\Users\\Public\\" -or $_.message -match "Image.*.*\\Users\\Contacts\\" -or $_.message -match "Image.*.*\\Users\\Searches\\" -or $_.message -match "Image.*.*\\config\\systemprofile\\" -or $_.message -match "Image.*.*\\Windows\\Fonts\\" -or $_.message -match "Image.*.*\\Windows\\IME\\" -or $_.message -match "Image.*.*\\Windows\\addins\\") -or ($_.message -match "Image.*.*\\$Recycle.bin") -or ($_.message -match "Image.*C:\\Perflogs\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
