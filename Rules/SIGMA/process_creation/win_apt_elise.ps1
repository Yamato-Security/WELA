# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*C:\Windows\SysWOW64\cmd.exe" -and $_.message -match "CommandLine.*.*\Windows\Caches\NavShExt.dll .*") -or $_.message -match "CommandLine.*.*\AppData\Roaming\MICROS~1\Windows\Caches\NavShExt.dll,Setting")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_apt_elise";
    $detectedMessage = "Detects Elise backdoor acitivty as used by APT32";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*C:\Windows\SysWOW64\cmd.exe" -and $_.message -match "CommandLine.*.*\Windows\Caches\NavShExt.dll .*") -or $_.message -match "CommandLine.*.*\AppData\Roaming\MICROS~1\Windows\Caches\NavShExt.dll,Setting")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
