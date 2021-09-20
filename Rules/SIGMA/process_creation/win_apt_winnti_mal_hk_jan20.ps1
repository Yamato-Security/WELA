# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*C:\Windows\Temp.*" -or $_.message -match "ParentImage.*.*\hpqhvind.exe.*") -and $_.message -match "Image.*C:\ProgramData\DRM.*") -or ($_.message -match "ParentImage.*C:\ProgramData\DRM.*" -and $_.message -match "Image.*.*\wmplayer.exe") -or ($_.message -match "ParentImage.*.*\Test.exe" -and $_.message -match "Image.*.*\wmplayer.exe") -or $_.message -match "Image.*C:\ProgramData\DRM\CLR\CLR.exe" -or ($_.message -match "ParentImage.*C:\ProgramData\DRM\Windows.*" -and $_.message -match "Image.*.*\SearchFilterHost.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_winnti_mal_hk_jan20";
    $detectedMessage = "Detects specific process characteristics of Winnti malware noticed in Dec/Jan 2020 in a campaign against Honk Kong universities";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*C:\\Windows\\Temp.*" -or $_.message -match "ParentImage.*.*\\hpqhvind.exe.*") -and $_.message -match "Image.*C:\\ProgramData\\DRM.*") -or ($_.message -match "ParentImage.*C:\\ProgramData\\DRM.*" -and $_.message -match "Image.*.*\\wmplayer.exe") -or ($_.message -match "ParentImage.*.*\\Test.exe" -and $_.message -match "Image.*.*\\wmplayer.exe") -or $_.message -match "Image.*C:\\ProgramData\\DRM\\CLR\\CLR.exe" -or ($_.message -match "ParentImage.*C:\\ProgramData\\DRM\\Windows.*" -and $_.message -match "Image.*.*\\SearchFilterHost.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
