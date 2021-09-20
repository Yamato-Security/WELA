# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\explorer.exe" -and $_.message -match "CommandLine.*.*C:\\Windows\\Temp\\meg.exe.*") -or (($_.ID -eq "1") -and $_.message -match "OriginalFileName.*meg.exe" -and  -not ($_.message -match "Image.*.*\\meg.exe")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_renamed_megasync";
    $detectedMessage = "Detects the execution of a renamed meg.exe of MegaSync during incident response engagements associated with ransomware families like Nefilim, Sodinokibi, Pysa, and Conti.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\explorer.exe" -and $_.message -match "CommandLine.*.*C:\\Windows\\Temp\\meg.exe.*") -or (($_.ID -eq "1") -and $_.message -match "OriginalFileName.*meg.exe" -and -not ($_.message -match "Image.*.*\\meg.exe")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
