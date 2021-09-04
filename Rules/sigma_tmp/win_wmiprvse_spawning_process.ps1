# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\WmiPrvSe.exe" -and  -not (($_.message -match "0x3e7" -or $_.message -match "null") -or ($_.message -match "0x3e7" -or $_.message -match "null") -or $_.message -match "User.*NT AUTHORITY\SYSTEM" -or ($_.message -match "Image.*.*\WmiPrvSE.exe" -or $_.message -match "Image.*.*\WerFault.exe"))) -and  -not (-not LogonId="*")) -and  -not (-not SubjectLogonId="*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_wmiprvse_spawning_process";
    $detectedMessage = "Detects wmiprvse spawning processes"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\WmiPrvSe.exe" -and -not (($_.message -match "0x3e7" -or $_.message -match "null") -or ($_.message -match "0x3e7" -or $_.message -match "null") -or $_.message -match "User.*NT AUTHORITY\SYSTEM" -or ($_.message -match "Image.*.*\WmiPrvSE.exe" -or $_.message -match "Image.*.*\WerFault.exe"))) -and -not (-not LogonId="*")) -and -not (-not SubjectLogonId="*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
