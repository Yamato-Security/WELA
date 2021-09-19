# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\odbcconf.exe" -and ($_.message -match "CommandLine.*.*-f.*" -or $_.message -match "CommandLine.*.*regsvr.*")) -or ($_.message -match "ParentImage.*.*\\odbcconf.exe" -and $_.message -match "Image.*.*\\rundll32.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_odbcconf";
    $detectedMessage = "Detects defence evasion attempt via odbcconf.exe execution to load DLL";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\odbcconf.exe" -and ($_.message -match "CommandLine.*.*-f.*" -or $_.message -match "CommandLine.*.*regsvr.*")) -or ($_.message -match "ParentImage.*.*\\odbcconf.exe" -and $_.message -match "Image.*.*\\rundll32.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
