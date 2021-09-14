# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "ParentImage.*.*UMWorkerProcess.exe" -and  -not (($_.message -match "Image.*.*wermgr.exe" -or $_.message -match "Image.*.*WerFault.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_cve_2021_26857_msexchange";
    $detectedMessage = "Detects possible successful exploitation for vulnerability described in CVE-2021-26857 by looking for |";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and $_.message -match "ParentImage.*.*UMWorkerProcess.exe" -and -not (($_.message -match "Image.*.*wermgr.exe" -or $_.message -match "Image.*.*WerFault.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
