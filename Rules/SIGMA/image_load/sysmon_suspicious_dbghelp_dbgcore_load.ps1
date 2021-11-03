# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and ((($_.ID -eq "7") -and (($_.message -match "ImageLoaded.*.*\dbghelp.dll" -or $_.message -match "ImageLoaded.*.*\dbgcore.dll") -and ($_.message -match "Image.*.*\msbuild.exe" -or $_.message -match "Image.*.*\cmd.exe" -or $_.message -match "Image.*.*\svchost.exe" -or $_.message -match "Image.*.*\rundll32.exe" -or $_.message -match "Image.*.*\powershell.exe" -or $_.message -match "Image.*.*\word.exe" -or $_.message -match "Image.*.*\excel.exe" -or $_.message -match "Image.*.*\powerpnt.exe" -or $_.message -match "Image.*.*\outlook.exe" -or $_.message -match "Image.*.*\monitoringhost.exe" -or $_.message -match "Image.*.*\wmic.exe" -or $_.message -match "Image.*.*\bash.exe" -or $_.message -match "Image.*.*\wscript.exe" -or $_.message -match "Image.*.*\cscript.exe" -or $_.message -match "Image.*.*\mshta.exe" -or $_.message -match "Image.*.*\regsvr32.exe" -or $_.message -match "Image.*.*\schtasks.exe" -or $_.message -match "Image.*.*\dnx.exe" -or $_.message -match "Image.*.*\regsvcs.exe" -or $_.message -match "Image.*.*\sc.exe" -or $_.message -match "Image.*.*\scriptrunner.exe")) -and  -not ($_.message -match "Image.*.*Visual Studio")) -or (($_.ID -eq "7") -and (($_.message -match "ImageLoaded.*.*\dbghelp.dll" -or $_.message -match "ImageLoaded.*.*\dbgcore.dll") -and $_.message -match "Signed.*FALSE") -and  -not ($_.message -match "Image.*.*Visual Studio")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_suspicious_dbghelp_dbgcore_load";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_suspicious_dbghelp_dbgcore_load";
            $detectedMessage = "Detects the load of dbghelp/dbgcore DLL (used to make memory dumps) by suspicious processes. Tools like ProcessHacker and some attacker tradecract use MiniDumpWriteDump
            API found in dbghelp.dll or dbgcore.dll. As an example, SilentTrynity C2 Framework has a module that leverages this API to dump the contents of Lsass.exe and
            transfer it over the network back to the attacker's machine.";
            $result = $event |  where { (($_.ID -eq "7") -and ((($_.ID -eq "7") -and (($_.message -match "ImageLoaded.*.*\\dbghelp.dll" -or $_.message -match "ImageLoaded.*.*\\dbgcore.dll") -and ($_.message -match "Image.*.*\\msbuild.exe" -or $_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\svchost.exe" -or $_.message -match "Image.*.*\\rundll32.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\word.exe" -or $_.message -match "Image.*.*\\excel.exe" -or $_.message -match "Image.*.*\\powerpnt.exe" -or $_.message -match "Image.*.*\\outlook.exe" -or $_.message -match "Image.*.*\\monitoringhost.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\bash.exe" -or $_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe" -or $_.message -match "Image.*.*\\mshta.exe" -or $_.message -match "Image.*.*\\regsvr32.exe" -or $_.message -match "Image.*.*\\schtasks.exe" -or $_.message -match "Image.*.*\\dnx.exe" -or $_.message -match "Image.*.*\\regsvcs.exe" -or $_.message -match "Image.*.*\\sc.exe" -or $_.message -match "Image.*.*\\scriptrunner.exe")) -and -not ($_.message -match "Image.*.*Visual Studio")) -or (($_.ID -eq "7") -and (($_.message -match "ImageLoaded.*.*\\dbghelp.dll" -or $_.message -match "ImageLoaded.*.*\\dbgcore.dll") -and $_.message -match "Signed.*FALSE") -and -not ($_.message -match "Image.*.*Visual Studio")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
