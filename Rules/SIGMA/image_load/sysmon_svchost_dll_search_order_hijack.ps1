# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and (($_.message -match "Image.*.*\svchost.exe") -and ($_.message -match "ImageLoaded.*.*\tsmsisrv.dll" -or $_.message -match "ImageLoaded.*.*\tsvipsrv.dll" -or $_.message -match "ImageLoaded.*.*\wlbsctrl.dll")) -and  -not (($_.message -match "ImageLoaded.*C:\Windows\WinSxS\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_svchost_dll_search_order_hijack";
    $detectedMessage = "IKEEXT and SessionEnv service, as they call LoadLibrary on files that do not exist within C:WindowsSystem32 by default. An attacker can place their"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "7") -and (($_.message -match "Image.*.*\svchost.exe") -and ($_.message -match "ImageLoaded.*.*\tsmsisrv.dll" -or $_.message -match "ImageLoaded.*.*\tsvipsrv.dll" -or $_.message -match "ImageLoaded.*.*\wlbsctrl.dll")) -and -not (($_.message -match "ImageLoaded.*C:\Windows\WinSxS\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
