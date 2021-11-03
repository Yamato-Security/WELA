# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\explorer.exe" -and $_.message -match "CommandLine.*.*C:\\Windows\\Temp\\meg.exe") -or (($_.ID -eq "1") -and $_.message -match "OriginalFileName.*meg.exe" -and  -not ($_.message -match "Image.*.*\\meg.exe")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_renamed_megasync";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_renamed_megasync";
            $detectedMessage = "Detects the execution of a renamed meg.exe of MegaSync during incident response engagements associated with ransomware families like Nefilim, Sodinokibi, Pysa, and Conti.";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\explorer.exe" -and $_.message -match "CommandLine.*.*C:\\Windows\\Temp\\meg.exe") -or (($_.ID -eq "1") -and $_.message -match "OriginalFileName.*meg.exe" -and -not ($_.message -match "Image.*.*\\meg.exe")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
