# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*\pwdump" -or $_.message -match "TargetFilename.*.*\kirbi" -or $_.message -match "TargetFilename.*.*\pwhashes" -or $_.message -match "TargetFilename.*.*\wce_ccache" -or $_.message -match "TargetFilename.*.*\wce_krbtkts" -or $_.message -match "TargetFilename.*.*\fgdump-log") -and ($_.message -match "TargetFilename.*.*\test.pwd" -or $_.message -match "TargetFilename.*.*\lsremora64.dll" -or $_.message -match "TargetFilename.*.*\lsremora.dll" -or $_.message -match "TargetFilename.*.*\fgexec.exe" -or $_.message -match "TargetFilename.*.*\wceaux.dll" -or $_.message -match "TargetFilename.*.*\SAM.out" -or $_.message -match "TargetFilename.*.*\SECURITY.out" -or $_.message -match "TargetFilename.*.*\SYSTEM.out" -or $_.message -match "TargetFilename.*.*\NTDS.out" -or $_.message -match "TargetFilename.*.*\DumpExt.dll" -or $_.message -match "TargetFilename.*.*\DumpSvc.exe" -or $_.message -match "TargetFilename.*.*\cachedump64.exe" -or $_.message -match "TargetFilename.*.*\cachedump.exe" -or $_.message -match "TargetFilename.*.*\pstgdump.exe" -or $_.message -match "TargetFilename.*.*\servpw.exe" -or $_.message -match "TargetFilename.*.*\servpw64.exe" -or $_.message -match "TargetFilename.*.*\pwdump.exe" -or $_.message -match "TargetFilename.*.*\procdump64.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_cred_dump_tools_dropped_files";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_cred_dump_tools_dropped_files";
            $detectedMessage = "Files with well-known filenames (parts of credential dump software or files produced by them) creation";
            $result = $event |  where { ($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*\\pwdump" -or $_.message -match "TargetFilename.*.*\\kirbi" -or $_.message -match "TargetFilename.*.*\\pwhashes" -or $_.message -match "TargetFilename.*.*\\wce_ccache" -or $_.message -match "TargetFilename.*.*\\wce_krbtkts" -or $_.message -match "TargetFilename.*.*\\fgdump-log") -and ($_.message -match "TargetFilename.*.*\\test.pwd" -or $_.message -match "TargetFilename.*.*\\lsremora64.dll" -or $_.message -match "TargetFilename.*.*\\lsremora.dll" -or $_.message -match "TargetFilename.*.*\\fgexec.exe" -or $_.message -match "TargetFilename.*.*\\wceaux.dll" -or $_.message -match "TargetFilename.*.*\\SAM.out" -or $_.message -match "TargetFilename.*.*\\SECURITY.out" -or $_.message -match "TargetFilename.*.*\\SYSTEM.out" -or $_.message -match "TargetFilename.*.*\\NTDS.out" -or $_.message -match "TargetFilename.*.*\\DumpExt.dll" -or $_.message -match "TargetFilename.*.*\\DumpSvc.exe" -or $_.message -match "TargetFilename.*.*\\cachedump64.exe" -or $_.message -match "TargetFilename.*.*\\cachedump.exe" -or $_.message -match "TargetFilename.*.*\\pstgdump.exe" -or $_.message -match "TargetFilename.*.*\\servpw.exe" -or $_.message -match "TargetFilename.*.*\\servpw64.exe" -or $_.message -match "TargetFilename.*.*\\pwdump.exe" -or $_.message -match "TargetFilename.*.*\\procdump64.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
