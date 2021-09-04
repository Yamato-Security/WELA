# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\lsass.exe" -and $_.message -match "GrantedAccess.*0x1fffff" -and ($_.message -match "CallTrace.*.*dbghelp.dll.*" -or $_.message -match "CallTrace.*.*dbgcore.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_lsass_memdump";
    $detectedMessage = "Detects process LSASS memory dump using procdump or taskmgr based on the CallTrace pointing to dbghelp.dll or dbgcore.dll for win10"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\lsass.exe" -and $_.message -match "GrantedAccess.*0x1fffff" -and ($_.message -match "CallTrace.*.*dbghelp.dll.*" -or $_.message -match "CallTrace.*.*dbgcore.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
