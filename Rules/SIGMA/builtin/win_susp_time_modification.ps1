# Get-WinEvent -LogName Security | where {($_.ID -eq "4616" -and  -not (((($_.message -match "ProcessName.*C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -or $_.message -match "ProcessName.*C:\Windows\System32\VBoxService.exe") -or ($_.message -match "ProcessName.*C:\Windows\System32\svchost.exe" -and $_.message -match "SubjectUserSid.*S-1-5-19"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_time_modification";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_time_modification";
            $detectedMessage = "Detect scenarios where a potentially unauthorized application or user is modifying the system time.";
            $result = $event |  where { ($_.ID -eq "4616" -and -not (((($_.message -match "ProcessName.*C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" -or $_.message -match "ProcessName.*C:\\Windows\\System32\\VBoxService.exe") -or ($_.message -match "ProcessName.*C:\\Windows\\System32\\svchost.exe" -and $_.message -match "SubjectUserSid.*S-1-5-19"))))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
