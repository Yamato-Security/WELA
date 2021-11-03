# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*C:\Windows\Temp" -or $_.message -match "ParentImage.*.*\hpqhvind.exe") -and $_.message -match "Image.*C:\ProgramData\DRM") -or ($_.message -match "ParentImage.*C:\ProgramData\DRM" -and $_.message -match "Image.*.*\wmplayer.exe") -or ($_.message -match "ParentImage.*.*\Test.exe" -and $_.message -match "Image.*.*\wmplayer.exe") -or $_.message -match "Image.*C:\ProgramData\DRM\CLR\CLR.exe" -or ($_.message -match "ParentImage.*C:\ProgramData\DRM\Windows" -and $_.message -match "Image.*.*\SearchFilterHost.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_winnti_mal_hk_jan20";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_winnti_mal_hk_jan20";
            $result = $event |  where { (($_.ID -eq "1") -and ((($_.message -match "ParentImage.*.*C:\\Windows\\Temp" -or $_.message -match "ParentImage.*.*\\hpqhvind.exe") -and $_.message -match "Image.*C:\\ProgramData\\DRM") -or ($_.message -match "ParentImage.*C:\\ProgramData\\DRM" -and $_.message -match "Image.*.*\\wmplayer.exe") -or ($_.message -match "ParentImage.*.*\\Test.exe" -and $_.message -match "Image.*.*\\wmplayer.exe") -or $_.message -match "Image.*C:\\ProgramData\\DRM\\CLR\\CLR.exe" -or ($_.message -match "ParentImage.*C:\\ProgramData\\DRM\\Windows" -and $_.message -match "Image.*.*\\SearchFilterHost.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
