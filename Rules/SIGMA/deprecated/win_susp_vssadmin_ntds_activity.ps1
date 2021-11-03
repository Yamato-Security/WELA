# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "vssadmin.exe Delete Shadows" -or $_.message -match "vssadmin create shadow /for=C:" -or $_.message -match "CommandLine.*copy \?\GLOBALROOT\Device\.*\windows\ntds\ntds.dit" -or $_.message -match "CommandLine.*copy \?\GLOBALROOT\Device\.*\config\SAM" -or $_.message -match "vssadmin delete shadows /for=C:" -or $_.message -match "reg SAVE HKLM\SYSTEM " -or $_.message -match "CommandLine.*esentutl.exe /y /vss .*\ntds.dit" -or $_.message -match "CommandLine.*esentutl.exe /y /vss .*\SAM" -or $_.message -match "CommandLine.*esentutl.exe /y /vss .*\SYSTEM")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_vssadmin_ntds_activity";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_vssadmin_ntds_activity";
            $detectedMessage = "Detects suspicious commands that could be related to activity that uses volume shadow copy to steal and retrieve hashes from the NTDS.dit file remotely";
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "vssadmin.exe Delete Shadows" -or $_.message -match "vssadmin create shadow /for=C:" -or $_.message -match "CommandLine.*copy \\?\\GLOBALROOT\\Device\\.*\\windows\\ntds\\ntds.dit" -or $_.message -match "CommandLine.*copy \\?\\GLOBALROOT\\Device\\.*\\config\\SAM" -or $_.message -match "vssadmin delete shadows /for=C:" -or $_.message -match "reg SAVE HKLM\\SYSTEM " -or $_.message -match "CommandLine.*esentutl.exe /y /vss .*\\ntds.dit" -or $_.message -match "CommandLine.*esentutl.exe /y /vss .*\\SAM" -or $_.message -match "CommandLine.*esentutl.exe /y /vss .*\\SYSTEM")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
