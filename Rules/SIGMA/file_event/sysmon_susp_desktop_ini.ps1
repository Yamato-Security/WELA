# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "11") -and $_.message -match "TargetFilename.*.*\desktop.ini" -and  -not (($_.message -match "C:\Windows\explorer.exe" -or $_.message -match "C:\Windows\System32\msiexec.exe" -or $_.message -match "C:\Windows\System32\mmc.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_desktop_ini";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_desktop_ini";
            $detectedMessage = "Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.";
            $result = $event |  where { (($_.ID -eq "11") -and $_.message -match "TargetFilename.*.*\\desktop.ini" -and -not (($_.message -match "C:\\Windows\\explorer.exe" -or $_.message -match "C:\\Windows\\System32\\msiexec.exe" -or $_.message -match "C:\\Windows\\System32\\mmc.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
