# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "Image.*.*\msiexec.exe" -and  -not (($_.message -match "Image.*C:\Windows\System32\.*" -or $_.message -match "Image.*C:\Windows\SysWOW64\.*" -or $_.message -match "Image.*C:\Windows\WinSxS\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_msiexec_cwd";
    $detectedMessage = "Detects suspicious msiexec process starts in an uncommon directory"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and $_.message -match "Image.*.*\msiexec.exe" -and -not (($_.message -match "Image.*C:\Windows\System32\.*" -or $_.message -match "Image.*C:\Windows\SysWOW64\.*" -or $_.message -match "Image.*C:\Windows\WinSxS\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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