# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.ID -eq "1") -and (($_.message -match "a53a02b997935fd8eedcb5f7abab9b9f" -or $_.message -match "e96a73c7bf33a464c510ede582318bf2") -or ($_.message -match "CommandLine.*.*.exe -S" -and $_.message -match "ParentImage.*.*\services.exe"))) -and  -not ($_.message -match "Image.*.*\clussvc.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_hack_wce";
    $detectedMessage = "Detects the use of Windows Credential Editor (WCE)";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.ID -eq "1") -and (($_.message -match "a53a02b997935fd8eedcb5f7abab9b9f" -or $_.message -match "e96a73c7bf33a464c510ede582318bf2") -or ($_.message -match "CommandLine.*.*.exe -S" -and $_.message -match "ParentImage.*.*\services.exe"))) -and -not ($_.message -match "Image.*.*\clussvc.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
