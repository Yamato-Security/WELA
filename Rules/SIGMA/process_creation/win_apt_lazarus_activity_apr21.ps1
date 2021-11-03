# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*mshta" -and $_.message -match "CommandLine.*.*.zip") -or (($_.message -match "C:\Windows\System32\wbem\wmiprvse.exe") -and ($_.message -match "C:\Windows\System32\mshta.exe")) -or (($_.message -match "ParentImage.*.*:\Users\Public\") -and ($_.message -match "C:\Windows\System32\rundll32.exe")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_lazarus_activity_apr21";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_lazarus_activity_apr21";
            $detectedMessage = "Detects different process creation events as described in Malwarebytes's threat report on Lazarus group activity";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*mshta" -and $_.message -match "CommandLine.*.*.zip") -or (($_.message -match "C:\\Windows\\System32\\wbem\\wmiprvse.exe") -and ($_.message -match "C:\\Windows\\System32\\mshta.exe")) -or (($_.message -match "ParentImage.*.*:\\Users\\Public\\") -and ($_.message -match "C:\\Windows\\System32\\rundll32.exe")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
