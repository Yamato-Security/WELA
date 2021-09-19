# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.message -match "Image.*.*\svchost.exe" -or $_.message -match "Image.*.*\taskhost.exe" -or $_.message -match "Image.*.*\lsm.exe" -or $_.message -match "Image.*.*\lsass.exe" -or $_.message -match "Image.*.*\services.exe" -or $_.message -match "Image.*.*\lsaiso.exe" -or $_.message -match "Image.*.*\csrss.exe" -or $_.message -match "Image.*.*\wininit.exe" -or $_.message -match "Image.*.*\winlogon.exe") -and  -not ($_.message -match "ParentImage.*.*\SavService.exe" -or ($_.message -match "ParentImage.*.*\System32\.*" -or $_.message -match "ParentImage.*.*\SysWOW64\.*"))) -and  -not (($_.message -match "ParentImage.*.*\Windows Defender\.*" -or $_.message -match "ParentImage.*.*\Microsoft Security Client\.*") -and $_.message -match "ParentImage.*.*\MsMpEng.exe")) -and  -not (-not ParentImage="*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_proc_wrong_parent";
    $detectedMessage = "Detect suspicious parent processes of well-known Windows processes";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ((($_.message -match "Image.*.*\svchost.exe" -or $_.message -match "Image.*.*\taskhost.exe" -or $_.message -match "Image.*.*\lsm.exe" -or $_.message -match "Image.*.*\lsass.exe" -or $_.message -match "Image.*.*\services.exe" -or $_.message -match "Image.*.*\lsaiso.exe" -or $_.message -match "Image.*.*\csrss.exe" -or $_.message -match "Image.*.*\wininit.exe" -or $_.message -match "Image.*.*\winlogon.exe") -and -not ($_.message -match "ParentImage.*.*\SavService.exe" -or ($_.message -match "ParentImage.*.*\System32\.*" -or $_.message -match "ParentImage.*.*\SysWOW64\.*"))) -and -not (($_.message -match "ParentImage.*.*\Windows Defender\.*" -or $_.message -match "ParentImage.*.*\Microsoft Security Client\.*") -and $_.message -match "ParentImage.*.*\MsMpEng.exe")) -and -not (-not ParentImage="*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
