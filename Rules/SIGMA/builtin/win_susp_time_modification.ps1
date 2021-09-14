# Get-WinEvent -LogName Security | where {($_.ID -eq "4616" -and  -not (((($_.message -match "ProcessName.*C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -or $_.message -match "ProcessName.*C:\Windows\System32\VBoxService.exe") -or ($_.message -match "ProcessName.*C:\Windows\System32\svchost.exe" -and $_.message -match "SubjectUserSid.*S-1-5-19"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_time_modification";
    $detectedMessage = "Detect scenarios where a potentially unauthorized application or user is modifying the system time.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4616" -and -not (((($_.message -match "ProcessName.*C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -or $_.message -match "ProcessName.*C:\Windows\System32\VBoxService.exe") -or ($_.message -match "ProcessName.*C:\Windows\System32\svchost.exe" -and $_.message -match "SubjectUserSid.*S-1-5-19"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
