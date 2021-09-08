# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "vssadmin.exe Delete Shadows" -or $_.message -match "vssadmin create shadow /for=C:" -or $_.message -match "CommandLine.*copy \?\GLOBALROOT\Device\.*\windows\ntds\ntds.dit" -or $_.message -match "CommandLine.*copy \?\GLOBALROOT\Device\.*\config\SAM" -or $_.message -match "vssadmin delete shadows /for=C:" -or $_.message -match "reg SAVE HKLM\SYSTEM " -or $_.message -match "CommandLine.*esentutl.exe /y /vss .*\ntds.dit.*" -or $_.message -match "CommandLine.*esentutl.exe /y /vss .*\SAM" -or $_.message -match "CommandLine.*esentutl.exe /y /vss .*\SYSTEM")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_vssadmin_ntds_activity";
    $detectedMessage = "Detects suspicious commands that could be related to activity that uses volume shadow copy to steal and retrieve hashes from the NTDS.dit file remotely";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "vssadmin.exe Delete Shadows" -or $_.message -match "vssadmin create shadow /for=C:" -or $_.message -match "CommandLine.*copy \?\GLOBALROOT\Device\.*\windows\ntds\ntds.dit" -or $_.message -match "CommandLine.*copy \?\GLOBALROOT\Device\.*\config\SAM" -or $_.message -match "vssadmin delete shadows /for=C:" -or $_.message -match "reg SAVE HKLM\SYSTEM " -or $_.message -match "CommandLine.*esentutl.exe /y /vss .*\ntds.dit.*" -or $_.message -match "CommandLine.*esentutl.exe /y /vss .*\SAM" -or $_.message -match "CommandLine.*esentutl.exe /y /vss .*\SYSTEM")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
