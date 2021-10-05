# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\\schtasks.exe" -and $_.message -match "CommandLine.*.* /create .*") -and  -not ($_.message -match "User.*NT AUTHORITY\\SYSTEM")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_schtask_creation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_schtask_creation";
            $detectedMessage = "Detects the creation of scheduled tasks in user session";
            $result = $event | where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\schtasks.exe" -and $_.message -match "CommandLine.*.* /create .*") -and -not ($_.message -match "User.*NT AUTHORITY\\SYSTEM")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
